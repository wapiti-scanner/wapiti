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
from typing import Generator, List, Optional

import httpx2
import spnego

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

        try:
            client = spnego.client(self.username, self.password, protocol="ntlm")
            request.headers[answer_header] = f"{scheme} {base64.b64encode(client.step()).decode('ascii')}"
            response = yield request

            # Some applications tie the handshake to a cookie set along with the challenge
            if response.cookies:
                httpx2.Cookies(response.cookies).set_cookie_header(request)

            token = _server_token(_challenges(response, challenge_header), scheme)
            if token is None:
                return

            request.headers[answer_header] = f"{scheme} {base64.b64encode(client.step(token)).decode('ascii')}"
        except (spnego.exceptions.SpnegoError, KeyError, IndexError, ValueError, struct.error):
            # A malformed challenge must not abort the scan: the caller gets the last response.
            # pyspnego doesn't wrap every parsing error of a token it can't decode.
            return

        yield request
