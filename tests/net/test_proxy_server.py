import asyncio
import gzip
import socket
import ssl
from contextlib import asynccontextmanager, suppress
from typing import Callable, List, Optional, Tuple

import h11
import httpx2
import pytest

from wapitiCore.net.proxy import CertificateAuthority, Flow, InterceptingProxy, ProxyResponse
from wapitiCore.net.proxy.server import parse_authority, forwardable_headers
from wapitiCore.net.proxy.streams import bridge, pump


class RecordedRequest:
    def __init__(self, method: str, target: str, headers: List[Tuple[bytes, bytes]], body: bytes):
        self.method = method
        self.target = target
        # Header names keep the casing seen on the wire
        self.headers = headers
        self.body = body

    def header(self, name: str) -> Optional[str]:
        for key, value in self.headers:
            if key.decode().lower() == name.lower():
                return value.decode()
        return None


def default_handler(request: RecordedRequest):
    return 200, [("Content-Type", "text/plain")], b"hello from " + request.target.encode()


class Upstream:
    """A real HTTP/1.1 server keeping track of what it receives."""

    def __init__(self, handler: Callable = default_handler, ssl_context: Optional[ssl.SSLContext] = None):
        self.handler = handler
        self.ssl_context = ssl_context
        self.requests: List[RecordedRequest] = []
        self.connections = 0
        self.port = 0
        self._server = None
        self._tasks = set()

    async def _handle(self, reader, writer):
        self.connections += 1
        self._tasks.add(asyncio.current_task())
        connection = h11.Connection(h11.SERVER)
        try:
            while True:
                event = connection.next_event()
                if event is h11.NEED_DATA:
                    connection.receive_data(await reader.read(65536))
                    continue

                if isinstance(event, h11.Request):
                    request = RecordedRequest(
                        event.method.decode(), event.target.decode(), event.headers.raw_items(), b""
                    )
                elif isinstance(event, h11.Data):
                    request.body += event.data
                elif isinstance(event, h11.EndOfMessage):
                    self.requests.append(request)
                    status, headers, body = self.handler(request)
                    headers = list(headers)
                    if not any(name.lower() in ("content-length", "transfer-encoding") for name, __ in headers):
                        headers.append(("Content-Length", str(len(body))))

                    writer.write(connection.send(h11.Response(status_code=status, headers=headers)))
                    if body and request.method != "HEAD":
                        writer.write(connection.send(h11.Data(data=body)))
                    writer.write(connection.send(h11.EndOfMessage()))
                    await writer.drain()
                    if connection.our_state is not h11.DONE or connection.their_state is not h11.DONE:
                        return
                    connection.start_next_cycle()
                else:
                    return
        except (ConnectionError, h11.ProtocolError):
            pass
        finally:
            writer.close()
            with suppress(Exception):
                await writer.wait_closed()

    async def __aenter__(self):
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0, ssl=self.ssl_context)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *args):
        self._server.close()
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)


class Recorder:
    """A proxy addon keeping every flow it sees."""

    def __init__(self):
        self.requests: List[Flow] = []
        self.responses: List[Flow] = []
        self.errors: List[Flow] = []

    async def request(self, flow: Flow):
        self.requests.append(flow)

    async def response(self, flow: Flow):
        self.responses.append(flow)

    async def error(self, flow: Flow):
        self.errors.append(flow)


def client_context(authority: CertificateAuthority) -> ssl.SSLContext:
    """SSL context of a client trusting nothing but the given authority."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(authority.certificate_path)
    return context


@asynccontextmanager
async def proxy_client(proxy: InterceptingProxy, trusted: CertificateAuthority):
    async with httpx2.AsyncClient(
        proxy=f"http://127.0.0.1:{proxy.port}",
        verify=client_context(trusted),
        timeout=10,
    ) as client:
        yield client


@pytest.fixture(name="authority")
def fixture_authority(tmp_path):
    return CertificateAuthority(str(tmp_path / "proxy-ca"))


@pytest.fixture(name="server_authority")
def fixture_server_authority(tmp_path):
    # The servers reached through the proxy get their certificates from another authority
    return CertificateAuthority(str(tmp_path / "server-ca"))


def test_parse_authority():
    assert parse_authority("example.com:8443", 443) == ("example.com", 8443)
    assert parse_authority("example.com", 80) == ("example.com", 80)
    assert parse_authority("[::1]:8443", 443) == ("::1", 8443)
    assert parse_authority("[::1]", 443) == ("::1", 443)
    assert parse_authority("user:secret@example.com:81", 80) == ("example.com", 81)
    with pytest.raises(ValueError):
        parse_authority("example.com:http", 80)


def test_forwardable_headers():
    headers = httpx2.Headers([
        (b"Host", b"example.com"),
        (b"Connection", b"keep-alive, X-Per-Hop"),
        (b"X-Per-Hop", b"1"),
        (b"Proxy-Authorization", b"Basic xxx"),
        (b"Content-Length", b"3"),
        (b"X-Kept", b"a"),
        (b"X-Kept", b"b"),
    ])
    assert forwardable_headers(headers) == [(b"Host", b"example.com"), (b"X-Kept", b"a"), (b"X-Kept", b"b")]


@pytest.mark.asyncio
async def test_plain_http_request(authority):
    recorder = Recorder()
    async with Upstream() as upstream, InterceptingProxy(authority, port=0, addons=[recorder]) as proxy:
        async with proxy_client(proxy, authority) as client:
            response = await client.get(
                f"http://127.0.0.1:{upstream.port}/some/path?a=1&b=%20",
                headers={"X-Custom-Header": "yolo"},
            )

    assert response.status_code == 200
    assert response.content == b"hello from /some/path?a=1&b=%20"

    assert len(recorder.requests) == len(recorder.responses) == 1
    flow = recorder.responses[0]
    assert flow.request.method == "GET"
    assert flow.request.url == f"http://127.0.0.1:{upstream.port}/some/path?a=1&b=%20"
    assert flow.request.headers["x-custom-header"] == "yolo"
    assert flow.response.status_code == 200
    assert flow.response.content == response.content

    received = upstream.requests[0]
    # The server gets an origin-form target and the headers with the casing used by the client
    assert received.target == "/some/path?a=1&b=%20"
    assert (b"X-Custom-Header", b"yolo") in received.headers
    assert received.header("Host") == f"127.0.0.1:{upstream.port}"
    assert received.header("Proxy-Connection") is None


@pytest.mark.asyncio
async def test_https_interception(authority, server_authority):
    recorder = Recorder()
    body = b"\x00\xffraw=bytes&not really a form\r\n" * 3000

    def handler(request):
        return 200, [("Content-Type", "application/octet-stream")], request.body[::-1]

    async with Upstream(handler, server_authority.ssl_context_for("localhost")) as upstream:
        async with InterceptingProxy(authority, port=0, addons=[recorder]) as proxy:
            # The client only trusts the proxy CA: the request succeeds because the proxy presents a
            # certificate it generated for "localhost"
            async with proxy_client(proxy, authority) as client:
                response = await client.post(f"https://localhost:{upstream.port}/upload", content=body)

    assert response.status_code == 200
    assert response.content == body[::-1]

    flow = recorder.responses[0]
    assert flow.request.url == f"https://localhost:{upstream.port}/upload"
    assert flow.request.method == "POST"
    # The addon and the server both get the exact bytes sent by the client
    assert flow.request.content == body
    assert upstream.requests[0].body == body
    assert upstream.requests[0].header("Content-Length") == str(len(body))


@pytest.mark.asyncio
async def test_chunked_request_body(authority):
    recorder = Recorder()

    async def chunks():
        yield b"first,"
        yield b"second,"
        yield b"third"

    async with Upstream() as upstream, InterceptingProxy(authority, port=0, addons=[recorder]) as proxy:
        async with proxy_client(proxy, authority) as client:
            response = await client.post(f"http://127.0.0.1:{upstream.port}/", content=chunks())

    assert response.status_code == 200
    assert recorder.requests[0].request.content == b"first,second,third"
    received = upstream.requests[0]
    assert received.body == b"first,second,third"
    # The body was buffered by the proxy so it is forwarded with its length
    assert received.header("Content-Length") == "18"
    assert received.header("Transfer-Encoding") is None


@pytest.mark.asyncio
async def test_redirection_is_not_followed(authority, server_authority):
    recorder = Recorder()

    def handler(_request):
        return 302, [("Location", "https://elsewhere.example/"), ("Content-Type", "text/html")], b"<a>moved</a>"

    async with Upstream(handler, server_authority.ssl_context_for("localhost")) as upstream:
        async with InterceptingProxy(authority, port=0, addons=[recorder]) as proxy:
            async with proxy_client(proxy, authority) as client:
                response = await client.get(f"https://localhost:{upstream.port}/")

    assert len(upstream.requests) == 1
    flow = recorder.responses[0]
    assert flow.response.status_code == 302
    assert flow.response.headers["location"] == "https://elsewhere.example/"
    assert flow.response.content == b"<a>moved</a>"
    # The client gets the redirection too, body included
    assert response.status_code == 302
    assert response.content == b"<a>moved</a>"


@pytest.mark.asyncio
async def test_compressed_content_is_left_untouched(authority):
    recorder = Recorder()
    compressed = gzip.compress(b"some text " * 100)

    def handler(_request):
        return 200, [("Content-Type", "text/plain"), ("Content-Encoding", "gzip")], compressed

    async with Upstream(handler) as upstream, InterceptingProxy(authority, port=0, addons=[recorder]) as proxy:
        async with proxy_client(proxy, authority) as client:
            response = await client.get(f"http://127.0.0.1:{upstream.port}/")

    assert recorder.responses[0].response.content == compressed
    assert response.headers["content-encoding"] == "gzip"
    assert response.content == b"some text " * 100


@pytest.mark.asyncio
async def test_chunked_response(authority):
    recorder = Recorder()

    def handler(_request):
        return 200, [("Content-Type", "text/plain"), ("Transfer-Encoding", "chunked")], b"chunked body"

    async with Upstream(handler) as upstream, InterceptingProxy(authority, port=0, addons=[recorder]) as proxy:
        async with proxy_client(proxy, authority) as client:
            response = await client.get(f"http://127.0.0.1:{upstream.port}/")

    assert response.content == b"chunked body"
    assert response.headers["content-length"] == "12"
    assert "transfer-encoding" not in response.headers
    assert recorder.responses[0].response.content == b"chunked body"


@pytest.mark.asyncio
async def test_addons_can_rewrite_request_and_response(authority):
    class Rewriter:
        async def request(self, flow: Flow):
            flow.request.headers["User-Agent"] = "Wapiti"
            flow.request.content = b"rewritten request"

        async def response(self, flow: Flow):
            flow.response.status_code = 200
            flow.response.content = b"rewritten response, longer than the original"
            del flow.response.headers["Set-Cookie"]

    def handler(_request):
        return 404, [("Content-Type", "text/plain"), ("Set-Cookie", "a=b")], b"original"

    async with Upstream(handler) as upstream, InterceptingProxy(authority, port=0, addons=[Rewriter()]) as proxy:
        async with proxy_client(proxy, authority) as client:
            response = await client.post(f"http://127.0.0.1:{upstream.port}/", content=b"original")

    received = upstream.requests[0]
    assert received.header("User-Agent") == "Wapiti"
    assert received.body == b"rewritten request"
    assert received.header("Content-Length") == "17"

    assert response.status_code == 200
    assert response.content == b"rewritten response, longer than the original"
    assert "set-cookie" not in response.headers


@pytest.mark.asyncio
async def test_addon_can_answer_in_place_of_the_server(authority):
    class Blocker:
        async def request(self, flow: Flow):
            flow.response = ProxyResponse(403, httpx2.Headers({"Content-Type": "text/plain"}), b"blocked")

    recorder = Recorder()
    async with Upstream() as upstream:
        async with InterceptingProxy(authority, port=0, addons=[Blocker(), recorder]) as proxy:
            async with proxy_client(proxy, authority) as client:
                response = await client.get(f"http://127.0.0.1:{upstream.port}/")

    assert response.status_code == 403
    assert response.content == b"blocked"
    assert not upstream.requests
    assert len(recorder.responses) == 1


@pytest.mark.asyncio
async def test_failing_addon_does_not_break_the_proxy(authority):
    class Broken:
        async def request(self, flow: Flow):
            raise RuntimeError("oops")

    recorder = Recorder()
    async with Upstream() as upstream:
        async with InterceptingProxy(authority, port=0, addons=[Broken(), recorder]) as proxy:
            async with proxy_client(proxy, authority) as client:
                response = await client.get(f"http://127.0.0.1:{upstream.port}/")

    assert response.status_code == 200
    assert len(recorder.responses) == 1


@pytest.mark.asyncio
async def test_keep_alive(authority, server_authority):
    recorder = Recorder()
    async with Upstream(ssl_context=server_authority.ssl_context_for("localhost")) as upstream:
        async with InterceptingProxy(authority, port=0, addons=[recorder]) as proxy:
            async with proxy_client(proxy, authority) as client:
                for index in range(3):
                    response = await client.get(f"https://localhost:{upstream.port}/{index}")
                    assert response.content == f"hello from /{index}".encode()

    assert [flow.request.target for flow in recorder.responses] == ["/0", "/1", "/2"]
    # The three requests went through a single tunnel and a single connection to the server
    assert upstream.connections == 1


@pytest.mark.asyncio
async def test_head_and_bodiless_responses(authority):
    def handler(request):
        if request.method == "HEAD":
            return 200, [("Content-Type", "text/plain"), ("Content-Length", "1234")], b""
        return 204, [], b""

    async with Upstream(handler) as upstream, InterceptingProxy(authority, port=0) as proxy:
        async with proxy_client(proxy, authority) as client:
            head_response = await client.head(f"http://127.0.0.1:{upstream.port}/")
            empty_response = await client.get(f"http://127.0.0.1:{upstream.port}/")
            # The connection must still be usable after responses without a body
            last_response = await client.head(f"http://127.0.0.1:{upstream.port}/")

    assert head_response.status_code == 200
    assert head_response.headers["content-length"] == "1234"
    assert head_response.content == b""
    assert empty_response.status_code == 204
    assert "content-length" not in empty_response.headers
    assert last_response.status_code == 200


@pytest.mark.asyncio
async def test_tunnel_when_not_intercepting(authority, server_authority):
    recorder = Recorder()
    seen = []

    def should_intercept(host: str, port: int) -> bool:
        seen.append((host, port))
        return False

    async with Upstream(ssl_context=server_authority.ssl_context_for("localhost")) as upstream:
        async with InterceptingProxy(
            authority, port=0, addons=[recorder], should_intercept=should_intercept
        ) as proxy:
            # Trusting the CA of the server proves the client talks to the real server...
            async with proxy_client(proxy, server_authority) as client:
                response = await client.get(f"https://localhost:{upstream.port}/tunneled")

            # ... and a client only trusting the proxy CA refuses the connection
            async with proxy_client(proxy, authority) as client:
                with pytest.raises(httpx2.ConnectError):
                    await client.get(f"https://localhost:{upstream.port}/tunneled")

    assert response.content == b"hello from /tunneled"
    assert seen[0] == ("localhost", upstream.port)
    assert not recorder.requests and not recorder.responses


@pytest.mark.asyncio
async def test_unreachable_server(authority):
    recorder = Recorder()
    # Grab a port nobody listens on
    async with Upstream() as upstream:
        closed_port = upstream.port

    await asyncio.sleep(0)
    async with InterceptingProxy(authority, port=0, addons=[recorder]) as proxy:
        async with proxy_client(proxy, authority) as client:
            response = await client.get(f"http://127.0.0.1:{closed_port}/")
            https_response = await client.get(f"https://127.0.0.1:{closed_port}/")

    assert response.status_code == 502
    assert https_response.status_code == 502
    assert len(recorder.errors) == 2
    assert recorder.errors[0].error
    assert not recorder.responses


@pytest.mark.asyncio
async def test_unreachable_server_when_tunneling(authority):
    async with Upstream() as upstream:
        closed_port = upstream.port

    async with InterceptingProxy(authority, port=0, should_intercept=lambda host, port: False) as proxy:
        async with proxy_client(proxy, authority) as client:
            with pytest.raises(httpx2.ProxyError):
                await client.get(f"https://127.0.0.1:{closed_port}/")


@pytest.mark.asyncio
@pytest.mark.parametrize("through_proxy", [False, True], ids=["direct", "browser already using the proxy"])
async def test_proxy_serves_its_certificate(authority, through_proxy):
    recorder = Recorder()
    async with InterceptingProxy(authority, port=0, addons=[recorder]) as proxy:
        proxy_url = f"http://127.0.0.1:{proxy.port}"
        async with httpx2.AsyncClient(proxy=proxy_url if through_proxy else None) as client:
            page = await client.get(f"http://localhost:{proxy.port}/")
            certificate = await client.get(f"http://localhost:{proxy.port}/wapiti-ca.pem")

    assert page.status_code == 200
    assert page.headers["content-type"].startswith("text/html")
    assert 'href="/wapiti-ca.pem"' in page.text
    assert authority.certificate_path in page.text

    assert certificate.status_code == 200
    assert certificate.headers["content-type"] == "application/x-x509-ca-cert"
    assert certificate.content == authority.certificate_pem
    # Those requests are not part of the browsing: addons don't see them
    assert not recorder.requests


@pytest.mark.asyncio
async def test_stop_closes_idle_connections(authority):
    async with Upstream() as upstream:
        proxy = InterceptingProxy(authority, port=0)
        await proxy.start()
        async with proxy_client(proxy, authority) as client:
            await client.get(f"http://127.0.0.1:{upstream.port}/")
            # The client keeps its connection to the proxy open: stopping must not wait for it
            await asyncio.wait_for(proxy.stop(), timeout=5)


class RawServer:
    """A TCP server running a coroutine for each connection, for what a well-behaved HTTP server can't do."""

    def __init__(self, handler: Callable, ssl_context: Optional[ssl.SSLContext] = None):
        self.handler = handler
        self.ssl_context = ssl_context
        self.port = 0
        self._server = None
        self._tasks = set()

    async def _handle(self, reader, writer):
        self._tasks.add(asyncio.current_task())
        try:
            await self.handler(reader, writer)
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
            with suppress(Exception):
                await writer.wait_closed()

    async def __aenter__(self):
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0, ssl=self.ssl_context)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *args):
        self._server.close()
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)


async def relay(reader_a, writer_a, reader_b, writer_b):
    async def write_a(data):
        writer_a.write(data)
        await writer_a.drain()

    async def write_b(data):
        writer_b.write(data)
        await writer_b.drain()

    await bridge(
        pump(lambda: reader_a.read(65536), write_b),
        pump(lambda: reader_b.read(65536), write_a),
        wait_for_both=False,
    )


class SocksServer(RawServer):
    """A minimal SOCKS5 proxy keeping track of what it was asked."""

    def __init__(self):
        super().__init__(self._socks)
        self.targets = []
        self.credentials = []

    async def _socks(self, reader, writer):
        __, count = await reader.readexactly(2)
        methods = await reader.readexactly(count)
        if 2 in methods:
            writer.write(b"\x05\x02")
            await reader.readexactly(1)
            username = await reader.readexactly((await reader.readexactly(1))[0])
            password = await reader.readexactly((await reader.readexactly(1))[0])
            self.credentials.append((username.decode(), password.decode()))
            writer.write(b"\x01\x00")
        else:
            writer.write(b"\x05\x00")

        __, __, __, address_type = await reader.readexactly(4)
        if address_type == 3:
            host = (await reader.readexactly((await reader.readexactly(1))[0])).decode()
        else:
            host = socket.inet_ntoa(await reader.readexactly(4))

        port = int.from_bytes(await reader.readexactly(2), "big")
        self.targets.append((host, port))

        server_reader, server_writer = await asyncio.open_connection(host, port)
        try:
            writer.write(b"\x05\x00\x00\x01" + bytes(6))
            await relay(reader, writer, server_reader, server_writer)
        finally:
            server_writer.close()


async def open_through_proxy(proxy: InterceptingProxy, port: int, mode: str, tls_context: ssl.SSLContext):
    """
    Returns a raw connection on which requests for the server listening on the given port can be written.

    Modes are "plain" (no tunnel, requests must use absolute URLs), "tunnel" (clear text inside a CONNECT
    tunnel) and "tls" (TLS inside a CONNECT tunnel).
    """
    reader, writer = await asyncio.open_connection("127.0.0.1", proxy.port)
    if mode != "plain":
        writer.write(f"CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n".encode())
        head = await reader.readuntil(b"\r\n\r\n")
        assert head.startswith(b"HTTP/1.1 200")

    if mode == "tls":
        await writer.start_tls(tls_context, server_hostname="localhost")

    return reader, writer


@pytest.mark.asyncio
async def test_event_stream_is_not_buffered(authority):
    recorder = Recorder()
    release = asyncio.Event()

    async def handler(reader, writer):
        await reader.readuntil(b"\r\n\r\n")
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\ndata: 1\n\n")
        await writer.drain()
        # The response never ends unless the test says so
        await release.wait()
        writer.write(b"data: 2\n\n")
        await writer.drain()

    async with RawServer(handler) as upstream, InterceptingProxy(authority, port=0, addons=[recorder]) as proxy:
        async with proxy_client(proxy, authority) as client:
            async with client.stream("GET", f"http://127.0.0.1:{upstream.port}/events") as response:
                iterator = response.aiter_bytes()
                # The first event reaches the client while the server is still holding the response
                first = await asyncio.wait_for(anext(iterator), timeout=5)
                assert not release.is_set()
                release.set()
                rest = b"".join([chunk async for chunk in iterator])

    assert first == b"data: 1\n\n"
    assert rest == b"data: 2\n\n"
    flow = recorder.responses[0]
    assert flow.response.streamed is True
    assert flow.response.content == b""
    assert flow.response.headers["content-type"] == "text/event-stream"


@pytest.mark.asyncio
@pytest.mark.parametrize("framing", ["Content-Length", "Transfer-Encoding"])
async def test_big_body_is_relayed_without_buffering(authority, framing):
    recorder = Recorder()
    body = bytes(range(256)) * 40

    def handler(_request):
        headers = [("Content-Type", "application/octet-stream")]
        if framing == "Transfer-Encoding":
            # No announced size: the proxy finds out the body is too big while reading it
            headers.append(("Transfer-Encoding", "chunked"))
        return 200, headers, body

    async with Upstream(handler) as upstream:
        async with InterceptingProxy(authority, port=0, addons=[recorder], max_buffered_body=1000) as proxy:
            async with proxy_client(proxy, authority) as client:
                response = await client.get(f"http://127.0.0.1:{upstream.port}/big")
                # The connection is still usable afterwards
                second_response = await client.get(f"http://127.0.0.1:{upstream.port}/big")

    assert response.content == body
    assert second_response.content == body
    assert recorder.responses[0].response.streamed is True
    assert recorder.responses[0].response.content == b""


@pytest.mark.asyncio
async def test_small_body_is_buffered(authority):
    recorder = Recorder()
    async with Upstream() as upstream:
        async with InterceptingProxy(authority, port=0, addons=[recorder], max_buffered_body=1000) as proxy:
            async with proxy_client(proxy, authority) as client:
                await client.get(f"http://127.0.0.1:{upstream.port}/small")

    assert recorder.responses[0].response.streamed is False
    assert recorder.responses[0].response.content == b"hello from /small"


@pytest.mark.asyncio
async def test_addon_can_replace_a_streamed_body(authority):
    class Replacer:
        async def response(self, flow: Flow):
            assert flow.response.streamed
            flow.response.content = b"not for you"
            flow.response.headers["Content-Type"] = "text/plain"

    def handler(_request):
        return 200, [("Content-Type", "application/zip")], b"PK" * 5000

    async with Upstream(handler) as upstream:
        async with InterceptingProxy(authority, port=0, addons=[Replacer()], max_buffered_body=1000) as proxy:
            async with proxy_client(proxy, authority) as client:
                response = await client.get(f"http://127.0.0.1:{upstream.port}/archive.zip")
                second_response = await client.get(f"http://127.0.0.1:{upstream.port}/archive.zip")

    assert response.content == b"not for you"
    assert response.headers["content-length"] == "11"
    assert second_response.content == b"not for you"


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["plain", "tunnel", "tls"])
async def test_websocket_upgrade_is_relayed(authority, server_authority, mode):
    recorder = Recorder()
    heads = []

    async def handler(reader, writer):
        heads.append(await reader.readuntil(b"\r\n\r\n"))
        writer.write(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
            b"Sec-WebSocket-Accept: whatever\r\n\r\n"
        )
        # Not the WebSocket protocol, but the proxy is not supposed to care
        while data := await reader.read(65536):
            writer.write(data.upper())
            await writer.drain()

    server_context = server_authority.ssl_context_for("localhost") if mode == "tls" else None
    async with RawServer(handler, server_context) as upstream:
        async with InterceptingProxy(authority, port=0, addons=[recorder]) as proxy:
            reader, writer = await open_through_proxy(proxy, upstream.port, mode, client_context(authority))
            target = f"http://localhost:{upstream.port}/socket" if mode == "plain" else "/socket"
            writer.write(
                f"GET {target} HTTP/1.1\r\nHost: localhost:{upstream.port}\r\nConnection: keep-alive, Upgrade\r\n"
                "Upgrade: websocket\r\nSec-WebSocket-Key: something\r\n\r\n".encode()
            )
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5)
            for message in (b"ping", b"x" * 100000, b"bye"):
                writer.write(message)
                echoed = await asyncio.wait_for(reader.readexactly(len(message)), timeout=5)
                assert echoed == message.upper()

            writer.close()

    assert head.startswith(b"HTTP/1.1 101")
    assert b"upgrade: websocket" in head.lower()
    assert b"sec-websocket-accept: whatever" in head.lower()
    # The server received the headers asking for the upgrade
    assert b"upgrade: websocket" in heads[0].lower()
    assert b"sec-websocket-key: something" in heads[0].lower()
    assert heads[0].startswith(b"GET /socket HTTP/1.1")

    flow = recorder.responses[0]
    assert flow.response.status_code == 101
    assert flow.request.url == f"{'https' if mode == 'tls' else 'http'}://localhost:{upstream.port}/socket"


@pytest.mark.asyncio
async def test_refused_upgrade_is_a_normal_response(authority):
    recorder = Recorder()
    async with Upstream() as upstream, InterceptingProxy(authority, port=0, addons=[recorder]) as proxy:
        async with proxy_client(proxy, authority) as client:
            url = f"http://127.0.0.1:{upstream.port}/"
            response = await client.get(url, headers={"Connection": "Upgrade", "Upgrade": "websocket"})
            second_response = await client.get(url)

    assert response.status_code == 200
    assert response.content == b"hello from /"
    assert second_response.status_code == 200
    assert recorder.responses[0].response.streamed is False


@pytest.mark.asyncio
async def test_clear_text_http_inside_a_tunnel(authority):
    recorder = Recorder()
    async with Upstream() as upstream, InterceptingProxy(authority, port=0, addons=[recorder]) as proxy:
        # The port is not 80 and yet the proxy must find out that this is not TLS
        reader, writer = await open_through_proxy(proxy, upstream.port, "tunnel", client_context(authority))
        writer.write(f"GET /clear HTTP/1.1\r\nHost: localhost:{upstream.port}\r\nConnection: close\r\n\r\n".encode())
        answer = await asyncio.wait_for(reader.read(-1), timeout=5)
        writer.close()

    assert answer.startswith(b"HTTP/1.1 200")
    assert answer.endswith(b"hello from /clear")
    assert recorder.responses[0].request.url == f"http://localhost:{upstream.port}/clear"


@pytest.mark.asyncio
@pytest.mark.parametrize("intercept", [True, False])
async def test_upstream_http_proxy(authority, server_authority, tmp_path, intercept):
    recorder = Recorder()
    upstream_recorder = Recorder()
    tunnels = []

    def upstream_should_intercept(host: str, port: int) -> bool:
        tunnels.append((host, port))
        return False

    async with Upstream(ssl_context=server_authority.ssl_context_for("localhost")) as secure_server:
        async with Upstream() as server:
            async with InterceptingProxy(
                CertificateAuthority(str(tmp_path / "upstream-ca")),
                port=0,
                addons=[upstream_recorder],
                should_intercept=upstream_should_intercept,
            ) as upstream_proxy:
                async with InterceptingProxy(
                    authority,
                    port=0,
                    addons=[recorder],
                    upstream_proxy=f"http://127.0.0.1:{upstream_proxy.port}",
                    should_intercept=lambda host, port: intercept,
                ) as proxy:
                    # When our proxy does not decrypt, the client talks to the real server
                    trusted = authority if intercept else server_authority
                    async with proxy_client(proxy, trusted) as client:
                        secure_response = await client.get(f"https://localhost:{secure_server.port}/secure")
                        response = await client.get(f"http://127.0.0.1:{server.port}/clear")

    assert secure_response.content == b"hello from /secure"
    assert response.content == b"hello from /clear"
    # Both requests went through the upstream proxy
    assert tunnels == [("localhost", secure_server.port)]
    assert [flow.request.url for flow in upstream_recorder.responses] == [f"http://127.0.0.1:{server.port}/clear"]
    assert len(recorder.responses) == (2 if intercept else 1)


@pytest.mark.asyncio
@pytest.mark.parametrize("intercept", [True, False])
@pytest.mark.parametrize("credentials", ["", "user:p%40ss@"])
async def test_upstream_socks_proxy(authority, server_authority, intercept, credentials):
    recorder = Recorder()
    async with Upstream(ssl_context=server_authority.ssl_context_for("localhost")) as secure_server:
        async with Upstream() as server, SocksServer() as socks:
            async with InterceptingProxy(
                authority,
                port=0,
                addons=[recorder],
                upstream_proxy=f"socks5://{credentials}127.0.0.1:{socks.port}",
                should_intercept=lambda host, port: intercept,
            ) as proxy:
                trusted = authority if intercept else server_authority
                async with proxy_client(proxy, trusted) as client:
                    secure_response = await client.get(f"https://localhost:{secure_server.port}/secure")
                    response = await client.get(f"http://127.0.0.1:{server.port}/clear")

    assert secure_response.content == b"hello from /secure"
    assert response.content == b"hello from /clear"
    assert socks.targets == [("localhost", secure_server.port), ("127.0.0.1", server.port)]
    assert socks.credentials == ([("user", "p@ss")] * 2 if credentials else [])


@pytest.mark.asyncio
@pytest.mark.parametrize("scheme", ["http", "socks5"])
async def test_unreachable_upstream_proxy(authority, server_authority, scheme):
    async with Upstream() as closed:
        closed_port = closed.port

    async with Upstream(ssl_context=server_authority.ssl_context_for("localhost")) as server:
        upstream_proxy = f"{scheme}://127.0.0.1:{closed_port}"
        async with InterceptingProxy(authority, port=0, upstream_proxy=upstream_proxy) as proxy:
            async with proxy_client(proxy, authority) as client:
                response = await client.get(f"https://localhost:{server.port}/")

        async with InterceptingProxy(
            authority, port=0, upstream_proxy=upstream_proxy, should_intercept=lambda host, port: False
        ) as proxy:
            async with proxy_client(proxy, server_authority) as client:
                with pytest.raises(httpx2.ProxyError):
                    await client.get(f"https://localhost:{server.port}/")

    assert response.status_code == 502
    # Nothing reached the server behind our back
    assert not server.requests


def test_unsupported_upstream_proxy(authority):
    with pytest.raises(ValueError):
        InterceptingProxy(authority, upstream_proxy="ftp://127.0.0.1:21")
