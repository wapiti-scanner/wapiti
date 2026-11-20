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
"""Objects handed to the addons of the intercepting proxy."""
import time
from dataclasses import dataclass, field
from email.message import Message
from email.utils import collapse_rfc2231_value
from http.cookiejar import http2time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl

import httpx2

DEFAULT_PORTS = {"http": 80, "https": 443}

# A multipart file entry, as expected by wapitiCore.net.Request: [field name, (file name, content, mime type)]
FileParameter = Tuple[str, Tuple[str, bytes, str]]


def media_type(headers: httpx2.Headers) -> str:
    """Returns the Content-Type without its parameters, in lowercase."""
    return headers.get("content-type", "").split(";")[0].strip().lower()


def _header_parameter(value: str, name: str) -> Optional[str]:
    """Extract a parameter from a header value like `form-data; name="field"; filename="a.txt"`."""
    message = Message()
    message["content-disposition"] = value
    parameter = message.get_param(name, header="content-disposition")
    if parameter is None:
        return None

    return collapse_rfc2231_value(parameter)


def parse_multipart(content_type: str, body: bytes) -> Tuple[List[Tuple[str, str]], List[FileParameter]]:
    """
    Parse a multipart/form-data body.

    Returns the simple fields and the file fields. The parsing is done by hand to give the files with their
    exact content, whatever the bytes they hold.
    """
    fields: List[Tuple[str, str]] = []
    files: List[FileParameter] = []
    boundary = _header_parameter(content_type, "boundary")
    if not boundary:
        return fields, files

    delimiter = b"--" + boundary.encode("latin-1")
    # What comes before the first delimiter and after the closing one is not part of the form
    for part in body.split(delimiter)[1:]:
        if part.startswith(b"--"):
            break

        raw_headers, separator, content = part.partition(b"\r\n\r\n")
        if not separator:
            continue

        # The line break before the next delimiter belongs to the delimiter, not to the content
        content = content.removesuffix(b"\r\n")
        headers = httpx2.Headers([
            tuple(item.strip() for item in line.split(b":", 1))
            for line in raw_headers.split(b"\r\n") if b":" in line
        ])
        disposition = headers.get("content-disposition", "")
        name = _header_parameter(disposition, "name")
        if name is None:
            continue

        filename = _header_parameter(disposition, "filename")
        if filename is None:
            fields.append((name, content.decode("utf-8", errors="replace")))
        else:
            files.append((name, (filename, content, headers.get("content-type", "application/octet-stream"))))

    return fields, files


def parse_set_cookie(value: str) -> Optional[Tuple[str, str, Dict[str, str]]]:
    """Split a Set-Cookie header into the name of the cookie, its value and its attributes (lowercase keys)."""
    pair, *raw_attributes = value.split(";")
    name, separator, cookie_value = pair.partition("=")
    name = name.strip()
    if not separator or not name:
        return None

    attributes = {}
    for raw_attribute in raw_attributes:
        key, __, attribute_value = raw_attribute.partition("=")
        if key.strip():
            attributes[key.strip().lower()] = attribute_value.strip()

    return name, cookie_value.strip(), attributes


def is_expired_cookie(attributes: Dict[str, str]) -> bool:
    """Tells if the attributes of a cookie ask for its removal."""
    if "max-age" in attributes:
        # Max-Age has precedence over Expires
        try:
            return int(attributes["max-age"]) <= 0
        except ValueError:
            return False

    expiration = http2time(attributes.get("expires", ""))
    return expiration is not None and expiration < time.time()


@dataclass
class ProxyRequest:
    """
    A request as sent by the client of the proxy.

    `target` is the request target exactly as it appeared on the request line (path and query string) and
    `content` holds the exact bytes of the body, once the transfer encoding (chunked) is removed.
    """
    method: str
    scheme: str
    host: str
    port: int
    target: str
    headers: httpx2.Headers
    content: bytes = b""
    http_version: str = "HTTP/1.1"

    @property
    def url(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        if DEFAULT_PORTS.get(self.scheme) != self.port:
            host = f"{host}:{self.port}"
        return f"{self.scheme}://{host}{self.target}"

    @property
    def media_type(self) -> str:
        return media_type(self.headers)

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", errors="replace")

    @property
    def urlencoded_form(self) -> List[Tuple[str, str]]:
        """Fields of the body if it is a urlencoded form, an empty list otherwise."""
        if self.media_type != "application/x-www-form-urlencoded":
            return []

        return parse_qsl(self.content.decode("utf-8", errors="replace"), keep_blank_values=True)

    @property
    def multipart_form(self) -> Tuple[List[Tuple[str, str]], List[FileParameter]]:
        """Simple fields and file fields of the body if it is a multipart form, two empty lists otherwise."""
        if self.media_type != "multipart/form-data":
            return [], []

        return parse_multipart(self.headers["content-type"], self.content)


@dataclass
class ProxyResponse:
    """
    A response as sent by the server.

    `content` holds the body as received on the wire once the transfer encoding (chunked) is removed:
    it is still compressed if the response carries a Content-Encoding header.

    `streamed` is True when the proxy relays the body to the client as it comes, without keeping it:
    endless responses (server-sent events), bodies too big to be buffered and protocol switches (101).
    `content` is then empty. An addon can still answer something else: give a `content` and the proxy
    sends it in place of the body of the server (set `streamed` to False to send an empty body).
    """
    status_code: int
    headers: httpx2.Headers
    content: bytes = b""
    reason: str = ""
    http_version: str = "HTTP/1.1"
    streamed: bool = False

    @property
    def media_type(self) -> str:
        return media_type(self.headers)

    @property
    def set_cookies(self) -> List[Tuple[str, str, Dict[str, str]]]:
        """Cookies set by the response, as (name, value, attributes) tuples."""
        cookies = [parse_set_cookie(value) for value in self.headers.get_list("set-cookie")]
        return [cookie for cookie in cookies if cookie is not None]

    def replace_body(self, content: bytes, content_type: str):
        """Answer the given content to the client instead of the body sent by the server."""
        self.content = content
        self.streamed = False
        self.headers["content-type"] = content_type
        # The new body is not compressed
        self.headers.pop("content-encoding", None)


@dataclass
class Flow:
    """A request and its response, travelling through the addons of the proxy."""
    request: ProxyRequest
    response: Optional[ProxyResponse] = None
    # Set when the proxy failed to obtain a response from the server, `response` is then the error page
    # generated by the proxy for its client
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
