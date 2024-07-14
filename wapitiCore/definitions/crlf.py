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


class CrlfFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "CRLF Injection"

    @classmethod
    def description(cls) -> str:
        return (
            "The term CRLF refers to Carriage Return (ASCII 13, \\r) Line Feed (ASCII 10, \\n)."
        ) + " " + (
            "A CRLF Injection attack occurs when a user manages to submit a CRLF into an application."
        ) + " " + (
            "This is most commonly done by modifying an HTTP parameter or URL."
        )

    @classmethod
    def references(cls) -> list:
        return [
            {
                "title": "OWASP: CRLF Injection",
                "url": "https://owasp.org/www-community/vulnerabilities/CRLF_Injection"
            },
            {
                "title": "Acunetix: What Are CRLF Injection Attacks",
                "url": "https://www.acunetix.com/websitesecurity/crlf-injection/"
            },
            {
                "title": "CWE-93: Improper Neutralization of CRLF Sequences ('CRLF Injection')",
                "url": "https://cwe.mitre.org/data/definitions/93.html"
            },
            {
                "title": "OWASP: Testing for HTTP Splitting Smuggling",
                "url": (
                    "https://owasp.org/www-project-web-security-testing-guide/latest/"
                    "4-Web_Application_Security_Testing/07-Input_Validation_Testing/"
                    "15-Testing_for_HTTP_Splitting_Smuggling"
                )
            }
        ]

    @classmethod
    def solution(cls) -> str:
        return (
            "Check the submitted parameters and do not allow CRLF to be injected when it is not expected."
        )

    @classmethod
    def short_name(cls) -> str:
        return cls.name()

    @classmethod
    def type(cls) -> str:
        return "vulnerability"

    @classmethod
    def wstg_code(cls) -> List[str]:
        return ["WSTG-INPV-15"]
