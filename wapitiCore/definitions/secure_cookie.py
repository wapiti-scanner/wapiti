#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2021-2023 Nicolas Surribas
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
from typing import List

from wapitiCore.definitions.base import FindingBase


class SecureCookieFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "Secure Flag cookie"

    @classmethod
    def description(cls) -> str:
        return (
            "The secure flag is an option that can be set by the application server when sending a new cookie to the "
            "user within an HTTP Response. "
            "The purpose of the secure flag is to prevent cookies from being observed by unauthorized parties due "
            "to the transmission of a the cookie in clear text."
        )

    @classmethod
    def references(cls) -> list:
        return [
            {
                "title": "OWASP: Testing for Cookies Attributes",
                "url": (
                    "https://owasp.org/www-project-web-security-testing-guide/stable/"
                    "4-Web_Application_Security_Testing/06-Session_Management_Testing/"
                    "02-Testing_for_Cookies_Attributes.html"
                )
            },
            {
                "title": "OWASP: Secure Cookie Attribute",
                "url": "https://owasp.org/www-community/controls/SecureCookieAttribute"
            }
        ]

    @classmethod
    def solution(cls) -> str:
        return "When generating the cookie, make sure to set the Secure Flag to True."

    @classmethod
    def short_name(cls) -> str:
        return cls.name()

    @classmethod
    def type(cls) -> str:
        return "vulnerability"

    @classmethod
    def wstg_code(cls) -> List[str]:
        return ["WSTG-SESS-02"]
