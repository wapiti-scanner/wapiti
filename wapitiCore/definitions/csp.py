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


class CspFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "Content Security Policy Configuration"

    @classmethod
    def description(cls) -> str:
        return (
            "Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain "
            "types of attacks, including Cross Site Scripting (XSS) and data injection attacks."
        )

    @classmethod
    def references(cls) -> list:
        return [
            {
                "title": "Mozilla: Content Security Policy (CSP)",
                "url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
            },
            {
                "title": "OWASP: Content Security Policy Cheat Sheet",
                "url": (
                    "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"
                )
            },
            {
                "title": "OWASP: How to do Content Security Policy (PDF)",
                "url": (
                    "https://owasp.org/www-pdf-archive/2019-02-22_-_How_do_I_Content_Security_Policy_-_Print.pdf"
                )
            },
            {
                "title": "OWASP: Content Security Policy",
                "url": (
                    "https://owasp.org/www-project-web-security-testing-guide/latest/"
                    "4-Web_Application_Security_Testing/"
                    "02-Configuration_and_Deployment_Management_Testing/12-Test_for_Content_Security_Policy"
                )
            }
        ]

    @classmethod
    def solution(cls) -> str:
        return (
            "Configuring Content Security Policy involves adding the Content-Security-Policy HTTP header to a web page "
            "and giving it values to control what resources the user agent is allowed to load for that page."
        )

    @classmethod
    def short_name(cls) -> str:
        return "CSP Configuration"

    @classmethod
    def type(cls) -> str:
        return "vulnerability"

    @classmethod
    def wstg_code(cls) -> List[str]:
        return ["WSTG-CONF-12", "OSHP-Content-Security-Policy"]
