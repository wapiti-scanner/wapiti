#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2023 Nicolas SURRIBAS
# Copyright (C) 2023-2024 Cyberwatch
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
import re
from typing import Iterable, Union, Set
from urllib.parse import urlparse, urlunparse

from tld import get_fld
from tld.exceptions import TldDomainNotFound

from wapitiCore.net import Request


def _lower_hostname(hostname: str) -> str:
    return hostname.lower() if hostname else hostname


def _lower_hostname_in_url(url: str) -> str:
    """Normalise scheme et hostname en minuscules (RFC 3986 : insensibles à la casse)."""
    url_parts = urlparse(url)
    if not url_parts.hostname:
        return url

    netloc = ""
    if url_parts.username:
        netloc += url_parts.username
        if url_parts.password:
            netloc += f":{url_parts.password}"
        netloc += "@"

    netloc += _lower_hostname(url_parts.hostname)
    if url_parts.port:
        netloc += f":{url_parts.port}"

    scheme = (url_parts.scheme or "").lower()
    return urlunparse((
        scheme,
        netloc,
        url_parts.path,
        url_parts.params,
        url_parts.query,
        url_parts.fragment
    ))


def is_same_domain(url: str, request: Request) -> bool:
    url_parts = urlparse(url)
    try:
        return _lower_hostname(get_fld(url)) == _lower_hostname(get_fld(request.url))
    except TldDomainNotFound:
        # Internal domain of IP
        # Check hostname instead of netloc to allow other ports
        return _lower_hostname(url_parts.hostname) == _lower_hostname(request.hostname)


class Scope:
    def __init__(self, base_request: Request, scope: str):
        self._scope: str = scope
        self._base_request: Request = base_request

    @property
    def name(self) -> str:
        return self._scope

    def check(self, resource: Union[Request, str]) -> bool:

        checked = None

        if not resource:
            return False

        if isinstance(resource, Request):
            url = resource.url
        else:
            url = resource

        if self._scope == "punk":
            # Life is short
            checked = True

        elif self._scope == "domain":
            checked = is_same_domain(url, self._base_request)

        elif self._scope == "subdomain":
            checked = _lower_hostname(urlparse(url).hostname) == _lower_hostname(self._base_request.hostname)

        elif self._scope == "folder":
            checked = _lower_hostname_in_url(url).startswith(_lower_hostname_in_url(self._base_request.path))

        elif self._scope == "page":
            checked = _lower_hostname_in_url(url.split("?")[0]) == _lower_hostname_in_url(self._base_request.path)

        # URL
        if checked is None:
            checked = _lower_hostname_in_url(url) == _lower_hostname_in_url(self._base_request.url)
        return checked

    def filter(self, resources: Iterable[Union[Request, str]]) -> Set[Union[Request, str]]:
        return {resource for resource in resources if self.check(resource)}


def wildcard_translate(pattern: str) -> re.Pattern:
    """Translate a wildcard PATTERN to a regular expression object that must be used with the 'match' function.

    This is largely inspired by fnmatch.translate.
    """

    res = ''
    for char in pattern:
        res += r'.*' if char == '*' else re.escape(char)
    return re.compile(r'(?ms)' + res + r'\Z')
