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
"""NTLM authentication for httpx2.

httpx-ntlm only works with httpx: its handler subclasses `httpx.Auth`, which an httpx2 client
rejects. This is the same handshake on top of pyspnego, as an `httpx2.Auth`.
"""
import base64
import binascii
import struct
from typing import Generator, List, Optional, Tuple

import httpx2
import spnego

# A handshake whose answer left through another connection than its challenge is started over, up to this
_MAX_HANDSHAKES = 3

# (challenge header sent by the server, header carrying our answer), per status code
_HEADERS_BY_STATUS = {
    401: ("WWW-Authenticate", "Authorization"),
    407: ("Proxy-Authenticate", "Proxy-Authorization"),
}


def _challenges(response: httpx2.Response, header: str) -> List[str]:
    """Return every challenge of the given header, one per item.

    A server may send several headers or a single one with comma-separated challenges.
    """
    return [
        challenge.strip()
        for value in response.headers.get_list(header)
        for challenge in value.split(",")
        if challenge.strip()
    ]


def _pick_scheme(challenges: List[str]) -> Optional[str]:
    """NTLM is preferred to Negotiate: with only a username and a password we can't do Kerberos."""
    schemes = {challenge.split(" ", 1)[0].lower() for challenge in challenges}
    if "ntlm" in schemes:
        return "NTLM"
    if "negotiate" in schemes:
        return "Negotiate"
    return None


def _server_token(challenges: List[str], scheme: str) -> Optional[bytes]:
    """Extract the token the server sent for our scheme, None if there is no usable one."""
    prefix = scheme.lower() + " "
    for challenge in challenges:
        if challenge.lower().startswith(prefix):
            try:
                return base64.b64decode(challenge[len(prefix):].strip(), validate=True)
            except (binascii.Error, ValueError):
                return None
    return None


class HttpNtlmAuth(httpx2.Auth):
    """HTTP NTLM authentication, for a server (401) or a proxy (407)."""

    def __init__(self, username: str, password: str):
        """
        @param username: username in the form "domain\\user"
        @param password: password of that account
        """
        self.username = username
        self.password = password

    def auth_flow(self, request: httpx2.Request) -> Generator[httpx2.Request, httpx2.Response, None]:
        # NTLM authenticates the connection, not the request: the three messages must use the same one
        request.headers["Connection"] = "Keep-Alive"
        response = yield request

        if response.status_code not in _HEADERS_BY_STATUS:
            return

        challenge_header, answer_header = _HEADERS_BY_STATUS[response.status_code]
        if answer_header in request.headers:
            # We already answered and the server still refuses: don't loop
            return

        scheme = _pick_scheme(_challenges(response, challenge_header))
        if scheme is None:
            return

        for _ in range(_MAX_HANDSHAKES):
            try:
                challenge_response, response = yield from self._handshake(
                    request, scheme, challenge_header, answer_header
                )
            except (spnego.exceptions.SpnegoError, KeyError, IndexError, ValueError, struct.error):
                # A malformed challenge must not abort the scan: the caller gets the last response.
                # pyspnego doesn't wrap every parsing error of a token it can't decode.
                return

            if response is None or response.status_code != challenge_response.status_code:
                return

            # The client pool sends each request over the first free connection, not over the one that
            # carried the challenge: if our answer left through another connection, the server never
            # saw that challenge and refused it. Start the handshake over.
            challenge_stream = challenge_response.extensions.get("network_stream")
            if challenge_stream is None or response.extensions.get("network_stream") is challenge_stream:
                # Same connection: the credentials really were refused
                return

    def _handshake(
            self,
            request: httpx2.Request,
            scheme: str,
            challenge_header: str,
            answer_header: str,
    ) -> Generator[httpx2.Request, httpx2.Response, Tuple[httpx2.Response, Optional[httpx2.Response]]]:
        """Send the negotiate then the authenticate message.

        Returns the response carrying the challenge, and the response to our answer (None if there was no
        challenge to answer).
        """
        # pyspnego's own NTLM implementation on every platform: on Windows it would otherwise go
        # through SSPI, which IIS refused in our tests while the pure-Python handshake succeeded
        client = spnego.client(self.username, self.password, protocol="ntlm", options=spnego.NegotiateOptions.use_ntlm)
        request.headers[answer_header] = f"{scheme} {base64.b64encode(client.step()).decode('ascii')}"
        challenge_response = yield request

        # Some applications tie the handshake to a cookie set along with the challenge
        if challenge_response.cookies:
            httpx2.Cookies(challenge_response.cookies).set_cookie_header(request)

        token = _server_token(_challenges(challenge_response, challenge_header), scheme)
        if token is None:
            return challenge_response, None

        request.headers[answer_header] = f"{scheme} {base64.b64encode(client.step(token)).decode('ascii')}"
        response = yield request
        return challenge_response, response
