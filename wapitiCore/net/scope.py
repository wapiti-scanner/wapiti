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
from urllib.parse import urlparse

from tld import get_fld
from tld.exceptions import TldDomainNotFound

from wapitiCore.net import Request


def is_same_domain(url: str, request: Request) -> bool:
    url_parts = urlparse(url)
    try:
        return get_fld(url) == get_fld(request.url)
    except TldDomainNotFound:
        # Internal domain of IP
        # Check hostname instead of netloc to allow other ports
        return url_parts.hostname == request.hostname


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
            checked = urlparse(url).hostname == self._base_request.hostname

        elif self._scope == "folder":
            checked = url.startswith(self._base_request.path)

        elif self._scope == "page":
            checked = url.split("?")[0] == self._base_request.path

        # URL
        if checked is None:
            checked = url == self._base_request.url
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
