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
from typing import List, Dict
from http.cookiejar import CookieJar, Cookie


def headless_cookies_to_cookiejar(headless_cookies: List[Dict]) -> CookieJar:
    cookie_jar = CookieJar()
    for cookie_dict in headless_cookies:
        # cookie_dict looks like this
        # [
        #   {
        #     'name': 'ASP.NET_SessionId',
        #     'value': 'fvej0j45uu212l55yen4bpff',
        #     'path': '/',
        #     'domain': 'testaspnet.vulnweb.com',
        #     'secure': False,
        #     'httpOnly': True
        #   }
        # ]
        hostname = cookie_dict["domain"]
        cookie = Cookie(
            version=0,
            name=cookie_dict["name"],
            value=cookie_dict["value"],
            port=cookie_dict.get("port"),
            port_specified=False,
            domain=hostname if hostname.startswith(".") else "." + hostname,
            domain_specified=True,
            domain_initial_dot=False,
            path=cookie_dict["path"],
            path_specified=True,
            secure=cookie_dict["secure"],
            expires=None,
            discard=True,
            comment=None,
            comment_url=None,
            rest={'HttpOnly': cookie_dict["httpOnly"]},
            rfc2109=False
        )
        cookie_jar.set_cookie(cookie)

    return cookie_jar


def mitm_jar_to_cookiejar(cookies: dict) -> CookieJar:
    cookie_jar = CookieJar()
    for scope in cookies:
        hostname: str
        port: int
        path: str

        hostname, port, path = scope
        for key, value in cookies[scope].items():
            cookie = Cookie(
                version=0,
                name=key,
                value=value,
                port=str(port),
                port_specified=False,
                domain=hostname if hostname.startswith(".") else "." + hostname,
                domain_specified=True,
                domain_initial_dot=False,
                path=path,
                path_specified=True,
                secure=True,
                expires=None,
                discard=True,
                comment=None,
                comment_url=None,
                rest={'HttpOnly': None},
                rfc2109=False
            )
            cookie_jar.set_cookie(cookie)
    return cookie_jar
