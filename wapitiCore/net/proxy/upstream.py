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
"""How the intercepting proxy reaches the servers: directly or through another (upstream) proxy."""
import asyncio
import ssl
from base64 import b64encode
from typing import Optional, Tuple
from urllib.parse import unquote, urlsplit

import httpcore2
from socksio import socks5

DEFAULT_PORTS = {"http": 80, "https": 443, "socks": 1080, "socks5": 1080, "socks5h": 1080}
MAX_CONNECTIONS = 100
Streams = Tuple[asyncio.StreamReader, asyncio.StreamWriter]


def insecure_ssl_context() -> ssl.SSLContext:
    # We are attacking the servers we talk to, no point in checking who they are
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def format_authority(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


class Upstream:
    """
    Gives connections to the servers, either directly or through an upstream proxy.

    `proxy_url` can use the http, https, socks, socks5 and socks5h schemes and may hold credentials.
    The three last ones are the same thing: SOCKS version 5 with hostnames resolved by the proxy.
    """

    def __init__(self, proxy_url: Optional[str] = None):
        self.scheme = ""
        self.host = ""
        self.port = 0
        self.credentials: Optional[Tuple[str, str]] = None

        if proxy_url:
            parts = urlsplit(proxy_url)
            if parts.scheme not in DEFAULT_PORTS or not parts.hostname:
                raise ValueError(f"Unsupported upstream proxy: {proxy_url}")

            self.scheme = parts.scheme
            self.host = parts.hostname
            self.port = parts.port or DEFAULT_PORTS[parts.scheme]
            if parts.username:
                self.credentials = (unquote(parts.username), unquote(parts.password or ""))

    @property
    def is_proxied(self) -> bool:
        return bool(self.scheme)

    @property
    def is_socks(self) -> bool:
        return self.scheme.startswith("socks")

    def build_pool(self) -> httpcore2.AsyncConnectionPool:
        """Returns the connection pool used to send the intercepted requests."""
        context = insecure_ssl_context()
        if not self.is_proxied:
            return httpcore2.AsyncConnectionPool(ssl_context=context, max_connections=MAX_CONNECTIONS)

        if self.is_socks:
            # Hostnames are always resolved by the SOCKS proxy, whatever the scheme says
            return httpcore2.AsyncSOCKSProxy(
                proxy_url=f"socks5://{format_authority(self.host, self.port)}",
                proxy_auth=self.credentials,
                ssl_context=context,
                max_connections=MAX_CONNECTIONS,
            )

        return httpcore2.AsyncHTTPProxy(
            proxy_url=f"{self.scheme}://{format_authority(self.host, self.port)}",
            proxy_auth=self.credentials,
            ssl_context=context,
            # httpcore2 refuses this argument when the proxy itself is not reached over TLS
            proxy_ssl_context=context if self.scheme == "https" else None,
            max_connections=MAX_CONNECTIONS,
        )

    async def open_tunnel(self, host: str, port: int) -> Streams:
        """
        Returns a raw connection to the given server, for the traffic the proxy relays without reading it.

        Failures are raised as OSError.
        """
        if not self.is_proxied:
            return await asyncio.open_connection(host, port)

        context = insecure_ssl_context() if self.scheme == "https" else None
        reader, writer = await asyncio.open_connection(self.host, self.port, ssl=context)
        try:
            if self.is_socks:
                await self._socks5_connect(reader, writer, host, port)
            else:
                await self._http_connect(reader, writer, host, port)
        except BaseException:
            writer.close()
            raise

        return reader, writer

    async def _http_connect(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, host: str, port: int):
        target = format_authority(host, port)
        lines = [f"CONNECT {target} HTTP/1.1", f"Host: {target}"]
        if self.credentials:
            token = b64encode(":".join(self.credentials).encode("utf-8")).decode("ascii")
            lines.append(f"Proxy-Authorization: Basic {token}")

        writer.write("\r\n".join(lines + ["", ""]).encode("latin-1"))
        await writer.drain()

        try:
            head = await reader.readuntil(b"\r\n\r\n")
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError) as exception:
            raise ConnectionError("The upstream proxy sent an invalid answer to CONNECT") from exception

        status_line = head.split(b"\r\n", 1)[0].decode("latin-1")
        parts = status_line.split(" ", 2)
        if len(parts) < 2 or not parts[1].startswith("2"):
            raise ConnectionError(f"The upstream proxy refused the tunnel: {status_line}")

    async def _socks5_connect(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, host: str, port: int):
        connection = socks5.SOCKS5Connection()

        async def exchange(request):
            connection.send(request)
            writer.write(connection.data_to_send())
            await writer.drain()
            data = await reader.read(4096)
            if not data:
                raise ConnectionError("The upstream SOCKS proxy closed the connection")
            return connection.receive_data(data)

        if self.credentials:
            method = socks5.SOCKS5AuthMethod.USERNAME_PASSWORD
        else:
            method = socks5.SOCKS5AuthMethod.NO_AUTH_REQUIRED

        try:
            reply = await exchange(socks5.SOCKS5AuthMethodsRequest([method]))
            if reply.method != method:
                raise ConnectionError("The upstream SOCKS proxy refused our authentication method")

            if self.credentials:
                username, password = (value.encode("utf-8") for value in self.credentials)
                reply = await exchange(socks5.SOCKS5UsernamePasswordRequest(username, password))
                if not reply.success:
                    raise ConnectionError("The upstream SOCKS proxy refused our credentials")

            reply = await exchange(
                socks5.SOCKS5CommandRequest.from_address(socks5.SOCKS5Command.CONNECT, (host, port))
            )
        except socks5.ProtocolError as exception:
            raise ConnectionError(f"Invalid answer from the upstream SOCKS proxy: {exception}") from exception

        if reply.reply_code != socks5.SOCKS5ReplyCode.SUCCEEDED:
            raise ConnectionError(f"The upstream SOCKS proxy could not connect: {reply.reply_code.name}")
