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


class SoftwareNameDisclosureFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "Fingerprint web technology"

    @classmethod
    def description(cls) -> str:
        return "The use of a web technology can be deducted due to the presence of its specific fingerprints."

    @classmethod
    def references(cls) -> list:
        return [
            {
                "title": "OWASP: Fingerprint Web Server",
                "url": (
                    "https://owasp.org/www-project-web-security-testing-guide/stable/"
                    "4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server.html"
                )
            },
            {
                "title": "OWASP: Fingerprint Web Application Framework",
                "url": (
                    "https://owasp.org/www-project-web-security-testing-guide/stable/"
                    "4-Web_Application_Security_Testing/"
                    "01-Information_Gathering/08-Fingerprint_Web_Application_Framework.html"
                )
            }
        ]

    @classmethod
    def solution(cls) -> str:
        return "This is only for informational purposes."

    @classmethod
    def short_name(cls) -> str:
        return cls.name()

    @classmethod
    def type(cls) -> str:
        return "additional"

    @classmethod
    def wstg_code(cls) -> List[str]:
        return ["WSTG-INFO-02", "WSTG-INFO-08"]
