#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
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


class XPathInjectionFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "XPATH Injection"

    @classmethod
    def description(cls) -> str:
        return (
            "XPath Injection attacks occur when a web site uses user-supplied information to construct an XPath query "
            "for XML data. "
            "By sending intentionally malformed information into the web site, an attacker can find out how "
            "the XML data is structured, or access data that they may not normally have access to."
        )

    @classmethod
    def references(cls) -> list:
        return [
            {
                "title": "OWASP: XPATH Injection",
                "url": "https://owasp.org/www-community/attacks/XPATH_Injection"
            },
            {
                "title": "CWE-91: XML Injection (aka Blind XPath Injection)",
                "url": "https://cwe.mitre.org/data/definitions/91.html"
            }
        ]

    @classmethod
    def solution(cls) -> str:
        return (
            "To protect against XPATH injection, you need to use a parameterized XPath interface if one is available, "
            "or escape the user input to make it safe to include in a dynamically constructed query. "
            "Instead, user input must be escaped or filtered or parameterized statements must be used."
        )

    @classmethod
    def short_name(cls) -> str:
        return "Unrestricted Upload"

    @classmethod
    def type(cls) -> str:
        return "XPATHi"

    @classmethod
    def wstg_code(cls) -> List[str]:
        return ["WSTG-INPV-09"]
