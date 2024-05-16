#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2006-2023 Nicolas SURRIBAS
# Copyright (C) 2021-2024 Cyberwatch
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

# Standard libraries
import warnings
from ast import literal_eval
from functools import lru_cache
from hashlib import md5
from http.client import IncompleteRead
from typing import List, Optional

# Third-parties
import httpx

from wapitiCore.net.web import make_absolute


warnings.filterwarnings(action='ignore', category=UserWarning, module='bs4')


class Response:
    def __init__(self, response: httpx.Response, url: Optional[str] = None):
        """Create a new Response object.

        @type response: Response
        @param response: a requests Response instance."""
        self._response = response
        self._url = url or str(self._response.url)

    # TODO: Should I remove this ? If not set in __init__ returns _response.url which in turns use _response.request.url
    # and the request attribute may be None...
    @property
    def url(self) -> str:
        """Returns the URL of the current Response object

        @rtype: str
        """
        return self._url

    @property
    def history(self) -> List["Response"]:
        """Returns a list of precedent webpages in case of redirection

        @rtype: list
        """
        return [Response(response) for response in self._response.history]

    @property
    def headers(self) -> httpx.Headers:
        """Returns the dictionary of HTTP headers as sent by the web-server.

        @rtype: dict
        """
        return self._response.headers

    # TODO: try to remove this?
    @property
    def sent_headers(self) -> httpx.Headers:
        return self._response.request.headers

    @property
    def cookies(self):
        return self._response.cookies

    @property
    @lru_cache(maxsize=2)
    def server(self) -> str:
        """The banner of the web-server software.

        @rtype: str
        """
        return self._response.headers.get("server", "")

    @property
    def is_plain(self) -> bool:
        """Returns True if the HTTP body is sent uncompressed, otherwise False.

        @rtype: bool
        """
        return self._response.headers.get("content-encoding", "identity") == "identity"

    @property
    @lru_cache(maxsize=2)
    def size(self) -> int:
        """Size of the web-page as specified in the Content-Length header,
        otherwise calculated from the actual HTML code.

        @rtype: int
        """
        if "content-length" in self._response.headers and self.is_plain:
            if self._response.headers.get("transfer-encoding", "") != "chunked":
                if "," in self._response.headers["content-length"]:
                    return int(self._response.headers["content-length"].split(",")[0].strip())
                if ";" in self._response.headers["content-length"]:
                    return int(self._response.headers["content-length"].split(";")[0].strip())

                return int(self._response.headers["content-length"])
        return len(self.bytes)

    @property
    @lru_cache(maxsize=2)
    def raw_size(self) -> int:
        """Size of the HTTP body sent as raw bytes by the server.

        @rtype: int
        """
        if "content-length" in self._response.headers:
            if self._response.headers.get("transfer-encoding", "") != "chunked":
                if "," in self._response.headers["content-length"]:
                    return int(self._response.headers["content-length"].split(",")[0].strip())
                if ";" in self._response.headers["content-length"]:
                    return int(self._response.headers["content-length"].split(";")[0].strip())

            return int(self._response.headers["content-length"])
        # Force consuming the body when in stream mode
        return len(self.bytes)

    @property
    @lru_cache(maxsize=2)
    def delay(self) -> float:
        """Time in seconds it took to fetch the web-page.

        @rtype: float
        """
        return self._response.elapsed.total_seconds()

    async def close(self):
        await self._response.aclose()

    async def read(self):
        await self._response.aread()

    @property
    def content(self) -> str:
        """HTML source code of the web-page as str"""
        try:
            return self._response.text
        except (httpx.ConnectError, OSError, IncompleteRead):
            return ""

    @property
    def bytes(self) -> bytes:
        """HTTP body response as raw bytes"""
        return self._response.content

    @property
    def json(self) -> Optional[dict]:
        if not self.content:
            return None

        try:
            return self._response.json()
        except ValueError:
            pass

        try:
            return literal_eval(self.content)
        except (ValueError, SyntaxError):
            pass

        return None

    @property
    @lru_cache(maxsize=2)
    def md5(self) -> str:
        """Return the MD5 hash (hex representation) of the content of the webpage"""
        return md5(self.bytes).hexdigest()

    @property
    @lru_cache(maxsize=2)
    def status(self) -> int:
        """Returns the HTTP status code as int"""
        return self._response.status_code

    @property
    @lru_cache(maxsize=2)
    def type(self) -> str:
        """Content-Type of the web-page as returned by the server."""
        return self._response.headers.get("content-type", "").lower()

    @property
    @lru_cache(maxsize=2)
    def redirection_url(self) -> str:
        """Returns the fixed URL sent through the Location header if set otherwise returns None."""
        if self._response.is_redirect:
            if "location" in self._response.headers:
                return make_absolute(self.url, self._response.headers["location"])
        return ""

    @property
    def is_directory_redirection(self) -> bool:
        if not self.redirection_url:
            return False
        if self.url + ("" if self.url.endswith("/") else "/") == self.redirection_url:
            return True
        return False

    @property
    def is_success(self) -> bool:
        """
        A property which is `True` for 2xx status codes, `False` otherwise.
        """
        return self._response.is_success

    @property
    def is_redirect(self) -> bool:
        """
        A property which is `True` for 3xx status codes, `False` otherwise.

        Note that not all responses with a 3xx status code indicate a URL redirect.

        """
        return self._response.is_redirect

    @property
    def is_client_error(self) -> bool:
        """
        A property which is `True` for 4xx status codes, `False` otherwise.
        """
        return self._response.is_client_error

    @property
    def is_server_error(self) -> bool:
        """
        A property which is `True` for 5xx status codes, `False` otherwise.
        """
        return self._response.is_server_error

    @property
    def is_error(self) -> bool:
        """
        A property which is `True` for 4xx and 5xx status codes, `False` otherwise.
        """
        return self._response.is_error

    @property
    def encoding(self) -> Optional[str]:
        """Return the detected encoding for the page."""
        if self._response.encoding:
            return self._response.encoding.upper()
        return None

    @property
    def apparent_encoding(self) -> Optional[str]:
        """Return the detected encoding for the page."""
        if self._response.charset_encoding:
            return self._response.charset_encoding.upper()
        return None

    @encoding.setter
    def encoding(self, new_encoding: str):
        """Change the encoding used for obtaining Response content"""
        self._response.encoding = new_encoding


def detail_response(response: Response) -> Optional[dict]:
    if not response:
        return None

    return {
        "status_code": response.status,
        "body": response.content,
        "headers": response.headers.multi_items()
    }
