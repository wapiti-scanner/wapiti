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


class XxeFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "XML External Entity"

    @classmethod
    def description(cls) -> str:
        return (
            "An XML External Entity attack is a type of attack against an application that parses XML input."
        ) + " " + (
            "This attack occurs when XML input containing a reference to an external entity is processed by a weakly "
            "configured XML parser."
        ) + " " + (
            "This attack may lead to the disclosure of confidential data, denial of service, "
            "server side request forgery, "
            "port scanning from the perspective of the machine where the parser is located, and other system impacts."
        )

    @classmethod
    def references(cls) -> list:
        return [
            {
                "title": "OWASP: XML External Entity (XXE) Processing",
                "url": "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"
            },
            {
                "title": "PortSwigger: What is XML external entity injection?",
                "url": "https://portswigger.net/web-security/xxe"
            },
            {
                "title": "CWE-611: Improper Restriction of XML External Entity Reference",
                "url": "https://cwe.mitre.org/data/definitions/611.html"
            },
            {
                "title": "OWASP: XML External Entity Prevention Cheat Sheet",
                "url": "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html"
            },
            {
                "title": "OWASP: XML Injection",
                "url": (
                    "https://owasp.org/www-project-web-security-testing-guide/latest/"
                    "4-Web_Application_Security_Testing/07-Input_Validation_Testing/07-Testing_for_XML_Injection"
                )
            }
        ]

    @classmethod
    def solution(cls) -> str:
        return "The safest way to prevent XXE is always to disable DTDs (External Entities) completely."

    @classmethod
    def short_name(cls) -> str:
        return "XXE"

    @classmethod
    def type(cls) -> str:
        return "XPATHi"

    @classmethod
    def wstg_code(cls) -> List[str]:
        return ["WSTG-INPV-07"]
