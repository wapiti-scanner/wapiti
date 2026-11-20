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
"""Byte streams helpers for the intercepting proxy."""
import asyncio
import ssl
from typing import Awaitable, Callable, Optional

READ_SIZE = 65536
# First byte of a TLS record carrying a handshake message, hence of any TLS connection
TLS_HANDSHAKE_RECORD = 0x16


def looks_like_tls(data: bytes) -> bool:
    return data[:1] == bytes([TLS_HANDSHAKE_RECORD])


class TLSServerStream:
    """
    Server side of a TLS connection, on top of an asyncio stream.

    asyncio can upgrade a connection to TLS (start_tls) but only if no byte of the TLS handshake was read
    yet. We have to read the first bytes sent by the client to know if it speaks TLS at all, so the
    encryption is done here, with the bytes already read given as `initial_data`.

    The object offers the few methods of StreamReader and StreamWriter used by the proxy.
    """

    def __init__(
            self,
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
            context: ssl.SSLContext,
            initial_data: bytes = b"",
    ):
        self._reader = reader
        self._writer = writer
        self._incoming = ssl.MemoryBIO()
        self._outgoing = ssl.MemoryBIO()
        self._tls = context.wrap_bio(self._incoming, self._outgoing, server_side=True)
        self._incoming.write(initial_data)

    def _flush(self):
        data = self._outgoing.read()
        if data:
            self._writer.write(data)

    async def _call(self, function: Callable, *args):
        """Call a method of the TLS object, feeding it with bytes of the client each time it asks for more."""
        while True:
            try:
                result = function(*args)
            except ssl.SSLWantReadError:
                self._flush()
                await self._writer.drain()
                data = await self._reader.read(READ_SIZE)
                if data:
                    self._incoming.write(data)
                else:
                    self._incoming.write_eof()
            else:
                # Reading can produce bytes to send too (TLS alerts, key updates)
                self._flush()
                return result

    async def do_handshake(self):
        await self._call(self._tls.do_handshake)
        await self._writer.drain()

    async def read(self, size: int = READ_SIZE) -> bytes:
        try:
            return await self._call(self._tls.read, size)
        except (ssl.SSLZeroReturnError, ssl.SSLEOFError):
            # The client closed the connection, properly or not
            return b""

    def write(self, data: bytes):
        if data:
            self._tls.write(data)
            self._flush()

    async def drain(self):
        await self._writer.drain()


async def pump(
        read: Callable[[], Awaitable[bytes]],
        write: Callable[[bytes], Awaitable[None]],
        on_eof: Optional[Callable[[], None]] = None,
):
    """Copy bytes from a stream to another one until the first one is exhausted."""
    while data := await read():
        await write(data)

    if on_eof:
        on_eof()


async def bridge(first: Awaitable, second: Awaitable, wait_for_both: bool):
    """
    Run the two directions of a relay.

    The relay always stops as soon as a direction fails. `wait_for_both` tells what to do when a direction
    ends normally: wait for the other one (TCP allows a peer to stop sending while it keeps receiving) or
    stop everything.
    """
    tasks = [asyncio.ensure_future(first), asyncio.ensure_future(second)]
    try:
        await asyncio.wait(
            tasks,
            return_when=asyncio.FIRST_EXCEPTION if wait_for_both else asyncio.FIRST_COMPLETED,
        )
    finally:
        for task in tasks:
            task.cancel()

        await asyncio.gather(*tasks, return_exceptions=True)
