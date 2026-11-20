#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2026 Nicolas SURRIBAS
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""
An intercepting HTTP/1.1 proxy.

Clients (a browser) use it as an explicit HTTP proxy. HTTPS connections are decrypted using certificates
generated on the fly by a local certificate authority. Each request/response pair is handed to addons that
can observe or rewrite it, the same way mitmproxy addons do.
"""
import asyncio
import ssl
from contextlib import AsyncExitStack, suppress
from typing import AsyncIterator, Callable, Iterable, List, Optional, Set, Tuple

import h11
import httpcore2
import httpx2

from wapitiCore.main.log import logging
from wapitiCore.net.proxy.ca import CA_CERT_FILENAME, CertificateAuthority
from wapitiCore.net.proxy.flow import Flow, ProxyRequest, ProxyResponse
from wapitiCore.net.proxy.streams import READ_SIZE, TLSServerStream, bridge, looks_like_tls, pump
from wapitiCore.net.proxy.upstream import Upstream, format_authority

RawHeaders = List[Tuple[bytes, bytes]]
Authority = Tuple[str, int]

# Bodies bigger than that are relayed to the client without being kept, so addons can't see them
MAX_BUFFERED_BODY = 16 * 1024 * 1024
EVENT_STREAM = "text/event-stream"

# Names a browser may use to reach a proxy listening on the loopback interface
LOCAL_NAMES = frozenset({"127.0.0.1", "localhost", "::1"})
CA_DOWNLOAD_PATH = "/wapiti-ca.pem"
WELCOME_PAGE = """<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Wapiti intercepting proxy</title></head>
<body>
<h1>Wapiti intercepting proxy</h1>
<p>To browse HTTPS websites through this proxy, your browser must trust the certificate authority of Wapiti.</p>
<p><a href="{path}">Download the certificate</a> and import it as a trusted authority for websites.</p>
<p>The same file is available on the machine running Wapiti: <code>{file}</code></p>
<p>Anyone holding the private key stored next to that file can impersonate any website for a browser trusting
this certificate: use a browser profile dedicated to your scans.</p>
</body>
</html>
"""

# Headers that only make sense for a single connection and must not be forwarded by a proxy (RFC 9110 7.6.1)
HOP_BY_HOP_HEADERS = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection", "te", "trailer",
    "transfer-encoding", "upgrade",
})

UPSTREAM_ERRORS = (
    httpcore2.NetworkError, httpcore2.ProtocolError, httpcore2.ProxyError, httpcore2.UnsupportedProtocol,
    OSError, ssl.SSLError,
)


def parse_authority(authority: str, default_port: int) -> Authority:
    """Split "host:port" (the target of a CONNECT request or the authority of a URL) into its parts."""
    # Credentials have nothing to do here but let's not treat them as a hostname
    authority = authority.rsplit("@", 1)[-1]
    host, separator, port = authority.rpartition(":")
    if not separator or port.endswith("]"):
        # No port given, the colon (if any) belongs to an IPv6 address
        host, port = authority, ""

    return host.strip("[]"), int(port) if port else default_port


def connection_tokens(headers: httpx2.Headers) -> Set[str]:
    return {value.strip().lower() for value in headers.get_list("connection", split_commas=True)}


def is_upgrade(headers: httpx2.Headers) -> bool:
    """Tells if the message asks for (request) or accepts (response) a switch to another protocol, like WebSocket."""
    return "upgrade" in headers and "upgrade" in connection_tokens(headers)


def forwardable_headers(headers: httpx2.Headers, keep_upgrade: bool = False) -> RawHeaders:
    """
    Returns the headers a proxy is allowed to forward, with their original order and casing.

    Content-Length is removed too because the caller has to compute it again from the (maybe rewritten) body.
    `keep_upgrade` preserves the headers negotiating a protocol switch, they are hop-by-hop headers otherwise.
    """
    excluded = set(HOP_BY_HOP_HEADERS)
    excluded.add("content-length")
    # A sender can declare more hop-by-hop headers in the Connection header
    excluded.update(connection_tokens(headers))

    result = [(name, value) for name, value in headers.raw if name.decode("latin-1").lower() not in excluded]
    if keep_upgrade:
        result.append((b"Connection", b"Upgrade"))
        result.append((b"Upgrade", headers["upgrade"].encode("latin-1")))

    return result


async def chain(chunks: List[bytes], iterator: AsyncIterator[bytes]) -> AsyncIterator[bytes]:
    for chunk in chunks:
        yield chunk

    async for chunk in iterator:
        yield chunk


class InterceptingProxy:
    """
    An intercepting proxy listening on a local port.

    Addons are objects with optional `request(flow)`, `response(flow)` and `error(flow)` coroutines.
    `request` is called before the request is sent to the server and can rewrite it, or set `flow.response`
    to answer in place of the server. `response` is called before the response is sent back to the client.
    `error` is called in place of `response` when the server could not be reached.

    `should_intercept(host, port)` tells if the traffic tunneled to a server (HTTPS mostly) must be decrypted.
    When it returns False the proxy blindly relays the bytes and addons see nothing.

    `upstream_proxy` is the URL of a proxy (http, https, socks5) used to reach the servers.
    """

    # pylint: disable=too-many-positional-arguments
    def __init__(
            self,
            certificate_authority: CertificateAuthority,
            port: int = 8080,
            host: str = "127.0.0.1",
            addons: Optional[Iterable[object]] = None,
            upstream_proxy: Optional[str] = None,
            should_intercept: Optional[Callable[[str, int], bool]] = None,
            timeout: float = 30.,
            idle_timeout: float = 120.,
            max_buffered_body: int = MAX_BUFFERED_BODY,
    ):
        self._ca = certificate_authority
        self._host = host
        self._port = port
        self._addons = list(addons or [])
        self._upstream = Upstream(upstream_proxy)
        self._should_intercept = should_intercept or (lambda host, port: True)
        self._timeout = timeout
        self._idle_timeout = idle_timeout
        self._max_buffered_body = max_buffered_body
        self._server: Optional[asyncio.AbstractServer] = None
        self._pool: Optional[httpcore2.AsyncConnectionPool] = None
        self._tasks: Set[asyncio.Task] = set()

    @property
    def port(self) -> int:
        """The listening port, useful when the proxy was asked to listen on port 0."""
        return self._port

    async def start(self):
        self._pool = self._upstream.build_pool()
        self._server = await asyncio.start_server(self._handle_client, self._host, self._port)
        self._port = self._server.sockets[0].getsockname()[1]

    async def stop(self):
        if self._server is None:
            return

        self._server.close()
        tasks = list(self._tasks)
        for task in tasks:
            task.cancel()

        await asyncio.gather(*tasks, return_exceptions=True)
        await self._server.wait_closed()
        await self._pool.aclose()
        self._server = None

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, *args):
        await self.stop()

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        task = asyncio.current_task()
        self._tasks.add(task)
        try:
            await self._serve_connection(reader, writer, "http", None)
        except (ConnectionError, asyncio.IncompleteReadError, asyncio.TimeoutError, ssl.SSLError):
            # The client went away or never completed what it started, nothing to do about it
            pass
        finally:
            self._tasks.discard(task)
            writer.close()
            with suppress(Exception):
                await writer.wait_closed()

    async def _next_event(self, connection: h11.Connection, reader, writer):
        while True:
            event = connection.next_event()
            if event is not h11.NEED_DATA:
                return event

            if connection.they_are_waiting_for_100_continue:
                writer.write(connection.send(h11.InformationalResponse(status_code=100, headers=[])))
                await writer.drain()

            connection.receive_data(await asyncio.wait_for(reader.read(READ_SIZE), self._idle_timeout))

    async def _serve_connection(
            self,
            reader,
            writer,
            scheme: str,
            authority: Optional[Authority],
            initial_data: bytes = b"",
    ):
        """
        Serve the HTTP requests of a client connection, until it gets closed.

        `reader` and `writer` are asyncio streams or a TLSServerStream.
        `authority` is the server the connection is tunneled to (after a CONNECT request). It is None for the
        connection to the proxy itself, where the server is given in each request line.
        """
        connection = h11.Connection(h11.SERVER)
        if initial_data:
            connection.receive_data(initial_data)

        while True:
            try:
                event = await self._next_event(connection, reader, writer)
                if not isinstance(event, h11.Request):
                    # ConnectionClosed: the client has no more requests for us
                    return

                body = bytearray()
                while True:
                    body_event = await self._next_event(connection, reader, writer)
                    if isinstance(body_event, h11.Data):
                        body += body_event.data
                    elif isinstance(body_event, h11.EndOfMessage):
                        break
                    else:
                        return
            except h11.RemoteProtocolError as exception:
                await self._send_error(connection, writer, 400, f"Bad request: {exception}")
                return

            if event.method == b"CONNECT":
                if authority is None:
                    await self._handle_connect(connection, reader, writer, event)
                else:
                    await self._send_error(connection, writer, 400, "CONNECT is not allowed inside a tunnel")
                return

            request = self._build_request(event, bytes(body), scheme, authority)
            if request is None:
                # Not a request for a proxy: someone opened our address in a browser
                await self._send_response(connection, writer, self._welcome(event.target))
            elif authority is None and self._is_for_us(request):
                # Same thing from a browser already configured to use us as a proxy
                await self._send_response(connection, writer, self._welcome(request.target.encode("latin-1")))
            else:
                await self._handle_flow(connection, reader, writer, Flow(request))

            if connection.our_state is not h11.DONE or connection.their_state is not h11.DONE:
                return

            connection.start_next_cycle()

    def _is_for_us(self, request: ProxyRequest) -> bool:
        return request.port == self._port and request.host.lower() in LOCAL_NAMES | {self._host.lower()}

    def _welcome(self, target: bytes) -> Flow:
        """
        Answer of the proxy to the requests sent to itself: a page giving the certificate of the authority,
        so a user can import it in the browser without looking for the file.
        """
        request = ProxyRequest("GET", "http", self._host, self._port, target.decode("latin-1"), httpx2.Headers())
        if target.split(b"?")[0] == CA_DOWNLOAD_PATH.encode():
            response = ProxyResponse(
                200,
                httpx2.Headers({
                    # With this type browsers offer to import the certificate instead of saving a file
                    "Content-Type": "application/x-x509-ca-cert",
                    "Content-Disposition": f'attachment; filename="{CA_CERT_FILENAME}"',
                }),
                self._ca.certificate_pem,
            )
        else:
            response = ProxyResponse(
                200,
                httpx2.Headers({"Content-Type": "text/html; charset=utf-8"}),
                WELCOME_PAGE.format(path=CA_DOWNLOAD_PATH, file=self._ca.certificate_path).encode("utf-8"),
            )

        return Flow(request, response)

    @staticmethod
    def _build_request(
            event: h11.Request,
            body: bytes,
            scheme: str,
            authority: Optional[Authority],
    ) -> Optional[ProxyRequest]:
        target = event.target.decode("latin-1")
        if authority is not None:
            host, port = authority
        else:
            # Plain HTTP request sent to the proxy: the request line holds an absolute URL.
            # We cut it by hand because the target must reach the server untouched.
            if not target.lower().startswith("http://"):
                return None

            netloc, slash, path = target[len("http://"):].partition("/")
            try:
                host, port = parse_authority(netloc, 80)
            except ValueError:
                return None

            target = slash + path or "/"

        return ProxyRequest(
            method=event.method.decode("latin-1"),
            scheme=scheme,
            host=host,
            port=port,
            target=target,
            # raw_items gives the header names with the casing used by the client
            headers=httpx2.Headers(event.headers.raw_items()),
            content=body,
            http_version=f"HTTP/{event.http_version.decode('latin-1')}",
        )

    async def _handle_connect(
            self,
            connection: h11.Connection,
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
            event: h11.Request,
    ):
        try:
            authority = parse_authority(event.target.decode("latin-1"), 443)
        except ValueError:
            await self._send_error(connection, writer, 400, "Invalid CONNECT target")
            return

        # Bytes the client may have sent right after its CONNECT request, without waiting for our answer
        early_data = connection.trailing_data[0]

        if not self._should_intercept(*authority):
            await self._tunnel(connection, reader, writer, authority, early_data)
            return

        writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await writer.drain()

        # A tunnel is not always used for TLS (browsers ask for one for ws:// URLs): the first bytes of the
        # client tell what it speaks
        first_bytes = early_data or await asyncio.wait_for(reader.read(READ_SIZE), self._idle_timeout)
        if not first_bytes:
            return

        if not looks_like_tls(first_bytes):
            await self._serve_connection(reader, writer, "http", authority, first_bytes)
            return

        stream = TLSServerStream(reader, writer, self._ca.ssl_context_for(authority[0]), first_bytes)
        await asyncio.wait_for(stream.do_handshake(), self._timeout)
        await self._serve_connection(stream, stream, "https", authority)

    async def _tunnel(
            self,
            connection: h11.Connection,
            client_reader: asyncio.StreamReader,
            client_writer: asyncio.StreamWriter,
            authority: Authority,
            early_data: bytes,
    ):
        """Blindly relay bytes between the client and a server we must not intercept."""
        try:
            server_reader, server_writer = await asyncio.wait_for(
                self._upstream.open_tunnel(*authority), self._timeout
            )
        except (OSError, asyncio.TimeoutError) as exception:
            await self._send_error(connection, client_writer, 502, f"Can't reach the server: {exception!r}")
            return

        def relay(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
            async def write(data: bytes):
                writer.write(data)
                await writer.drain()

            def half_close():
                # Tell the peer that nothing more will come, it can still send us its own data
                with suppress(OSError, RuntimeError):
                    writer.write_eof()

            return pump(lambda: reader.read(READ_SIZE), write, half_close)

        try:
            client_writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
            server_writer.write(early_data)
            await bridge(
                relay(client_reader, server_writer),
                relay(server_reader, client_writer),
                wait_for_both=True,
            )
        finally:
            server_writer.close()

    async def _run_addons(self, hook: str, flow: Flow):
        for addon in self._addons:
            method = getattr(addon, hook, None)
            if method is None:
                continue

            try:
                await method(flow)
            except Exception as exception:  # pylint: disable=broad-except
                # A broken addon must not take the connection down with it
                logging.error("Proxy addon %s failed in %s hook: %r", type(addon).__name__, hook, exception)

    async def _handle_flow(self, connection: h11.Connection, reader, writer, flow: Flow):
        # The connection to the server is released when leaving the stack, whatever happens
        async with AsyncExitStack() as stack:
            await self._run_addons("request", flow)
            server_response = None
            pending_body = None
            if flow.response is None:
                server_response, pending_body = await self._forward(flow, stack)

            await self._run_addons("error" if flow.error else "response", flow)

            if server_response is not None and server_response.status == 101 and flow.response.status_code == 101:
                await self._switch_protocols(connection, reader, writer, flow, server_response)
                return

            await self._send_response(connection, writer, flow, pending_body)

    def _must_stream(self, headers: httpx2.Headers) -> bool:
        """Tells from its headers if the body of a response must be relayed without being buffered."""
        if headers.get("content-type", "").lower().startswith(EVENT_STREAM):
            # Server-sent events: the body never ends
            return True

        try:
            return int(headers.get("content-length", "0")) > self._max_buffered_body
        except ValueError:
            return False

    async def _forward(
            self,
            flow: Flow,
            stack: AsyncExitStack,
    ) -> Tuple[Optional[httpcore2.Response], Optional[AsyncIterator[bytes]]]:
        """
        Send the request to the server and store its response in the flow.

        Returns the response of the server (None if we got none) and, when its body is not buffered, an
        iterator giving that body.
        """
        request = flow.request
        upgrade = is_upgrade(request.headers)
        headers = forwardable_headers(request.headers, keep_upgrade=upgrade)
        if request.content or "content-length" in request.headers or "transfer-encoding" in request.headers:
            headers.append((b"Content-Length", str(len(request.content)).encode()))

        if "host" not in request.headers:
            host = format_authority(request.host, request.port) if ":" in request.host else request.host
            headers.insert(0, (b"Host", host.encode("latin-1")))

        url = httpcore2.URL(
            scheme=request.scheme,
            host=request.host,
            port=request.port,
            target=request.target.encode("latin-1"),
        )
        timeouts = {key: self._timeout for key in ("connect", "read", "write", "pool")}
        if EVENT_STREAM in request.headers.get("accept", "").lower():
            # A stream of events can stay silent for a long time
            timeouts["read"] = None

        buffered: List[bytes] = []
        pending_body = None
        try:
            # httpcore2 follows no redirection, handles no cookie and decodes no content: what we get is what
            # the server sent.
            response = await stack.enter_async_context(
                self._pool.stream(
                    request.method,
                    url,
                    headers=headers,
                    content=request.content,
                    extensions={"timeout": timeouts},
                )
            )
            response_headers = httpx2.Headers(response.headers)
            switching = response.status == 101 and upgrade
            has_body = request.method != "HEAD" and response.status not in (204, 304) and not switching

            if has_body:
                chunks = response.aiter_stream()
                if self._must_stream(response_headers):
                    pending_body = chunks
                else:
                    size = 0
                    async for chunk in chunks:
                        buffered.append(chunk)
                        size += len(chunk)
                        if size > self._max_buffered_body:
                            # Too big to be kept: the client gets what we already have then the rest
                            pending_body = chain(buffered, chunks)
                            buffered = []
                            break
        except httpcore2.TimeoutException as exception:
            self._set_error(flow, 504, f"The server did not answer in time: {exception!r}")
            return None, None
        except UPSTREAM_ERRORS as exception:
            self._set_error(flow, 502, f"Can't get a response from the server: {exception!r}")
            return None, None

        if response.status < 200 and not switching:
            self._set_error(flow, 502, f"Unexpected status code {response.status} from the server")
            return None, None

        flow.response = ProxyResponse(
            status_code=response.status,
            headers=response_headers,
            content=b"".join(buffered),
            reason=response.extensions.get("reason_phrase", b"").decode("latin-1"),
            http_version=response.extensions.get("http_version", b"HTTP/1.1").decode("latin-1"),
            streamed=switching or pending_body is not None,
        )
        return response, pending_body

    @staticmethod
    def _set_error(flow: Flow, status_code: int, message: str):
        flow.error = message
        flow.response = ProxyResponse(
            status_code=status_code,
            headers=httpx2.Headers({"Content-Type": "text/plain; charset=utf-8"}),
            content=message.encode("utf-8"),
        )

    @staticmethod
    async def _switch_protocols(
            connection: h11.Connection,
            reader,
            writer,
            flow: Flow,
            server_response: httpcore2.Response,
    ):
        """
        The server accepted to switch to another protocol (WebSocket): tell it to the client then relay the
        bytes between them, without trying to understand them.
        """
        server = server_response.extensions["network_stream"]
        headers = forwardable_headers(flow.response.headers, keep_upgrade=is_upgrade(flow.response.headers))
        writer.write(connection.send(h11.InformationalResponse(status_code=101, headers=headers)))
        await writer.drain()

        # Bytes of the new protocol the client may have sent along with its request
        early_data = connection.trailing_data[0]
        if early_data:
            await server.write(early_data)

        async def write_to_client(data: bytes):
            writer.write(data)
            await writer.drain()

        with suppress(*UPSTREAM_ERRORS, httpcore2.TimeoutException):
            await bridge(
                pump(lambda: reader.read(READ_SIZE), server.write),
                # No timeout: such connections are meant to stay silent for long periods
                pump(lambda: server.read(READ_SIZE, timeout=None), write_to_client),
                wait_for_both=False,
            )

    @staticmethod
    async def _send_response(
            connection: h11.Connection,
            writer,
            flow: Flow,
            pending_body: Optional[AsyncIterator[bytes]] = None,
    ):
        response = flow.response
        headers = forwardable_headers(response.headers)
        has_body = flow.request.method != "HEAD" and response.status_code not in (204, 304)
        # An addon may have chosen to answer something else than the body we were about to relay
        relayed = has_body and pending_body is not None and response.streamed and not response.content

        if relayed:
            # We don't know the size of the body: without Content-Length, h11 picks the right framing for
            # the client (chunked encoding, or closing the connection for HTTP/1.0)
            pass
        elif has_body:
            headers.append((b"Content-Length", str(len(response.content)).encode()))
        elif "content-length" in response.headers and response.status_code != 204:
            # Answers to HEAD requests and 304 responses announce the size of a body they don't send
            headers.append((b"Content-Length", response.headers["content-length"].encode("latin-1")))

        writer.write(
            connection.send(
                h11.Response(
                    status_code=response.status_code,
                    headers=headers,
                    reason=response.reason.encode("latin-1"),
                )
            )
        )
        if relayed:
            await writer.drain()
            try:
                async for chunk in pending_body:
                    if chunk:
                        writer.write(connection.send(h11.Data(data=chunk)))
                        await writer.drain()
            except (*UPSTREAM_ERRORS, httpcore2.TimeoutException) as exception:
                # Too late for an error page: cutting the connection is the only way to tell the client that
                # the body is incomplete
                raise ConnectionError("The server failed while sending its response") from exception
        elif has_body and response.content:
            writer.write(connection.send(h11.Data(data=response.content)))

        writer.write(connection.send(h11.EndOfMessage()))
        await writer.drain()

    @staticmethod
    async def _send_error(connection: h11.Connection, writer, status_code: int, message: str):
        """Answer to a request the proxy can't or won't process, then give up on the connection."""
        body = message.encode("utf-8")
        headers = [
            (b"Content-Type", b"text/plain; charset=utf-8"),
            (b"Content-Length", str(len(body)).encode()),
            (b"Connection", b"close"),
        ]
        with suppress(h11.LocalProtocolError):
            writer.write(connection.send(h11.Response(status_code=status_code, headers=headers)))
            writer.write(connection.send(h11.Data(data=body)))
            writer.write(connection.send(h11.EndOfMessage()))
            await writer.drain()
