#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2023 Nicolas SURRIBAS
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
from typing import Optional
from dataclasses import dataclass
from http.cookiejar import CookieJar

from wapitiCore.net import Request

DEFAULT_UA = "Mozilla/5.0 (Windows NT 6.1; rv:45.0) Gecko/20100101 Firefox/45.0"


@dataclass
class HttpCredential:
    username: str
    password: str
    method: str = "basic"


@dataclass
class FormCredential:
    username: str
    password: str
    url: str


@dataclass
class RawCredential:
    data: str
    url: str
    enctype: Optional[str] = None


@dataclass
class CrawlerConfiguration:
    base_request: Request
    timeout: float = 10.0
    secure: bool = False
    compression: bool = True
    user_agent: str = DEFAULT_UA
    proxy: Optional[str] = None
    http_credential: Optional[HttpCredential] = None
    cookies: Optional[CookieJar] = None
    stream: bool = False
    headers: Optional[dict] = None
    drop_cookies: bool = False
