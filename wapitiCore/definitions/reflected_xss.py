#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
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


class XssFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "Reflected Cross Site Scripting"

    @classmethod
    def description(cls) -> str:
        return (
            "Cross-site scripting (XSS) is a type of computer security vulnerability typically found in web "
            "applications which allow code injection by malicious web users into the web pages viewed by other users. "
            "Examples of such code include HTML code and client-side scripts."
        )

    @classmethod
    def references(cls) -> list:
        return [
            {
                "title": "OWASP: Cross Site Scripting (XSS)",
                "url": "https://owasp.org/www-community/attacks/xss/"
            },
            {
                "title": "Wikipedia: Cross-site scripting",
                "url": "https://en.wikipedia.org/wiki/Cross-site_scripting"
            },
            {
                "title": "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
                "url": "https://cwe.mitre.org/data/definitions/79.html"
            },
            {
                "title": "OWASP: Reflected Cross Site Scripting",
                "url": (
                    "https://owasp.org/www-project-web-security-testing-guide/latest/"
                    "4-Web_Application_Security_Testing/07-Input_Validation_Testing/"
                    "01-Testing_for_Reflected_Cross_Site_Scripting"
                )
            }
        ]

    @classmethod
    def solution(cls) -> str:
        return (
            "The best way to protect a web application from XSS attacks is ensure that the application performs "
            "validation of all headers, cookies, query strings, form fields, and hidden fields. "
            "Encoding user supplied output in the server side can also defeat XSS vulnerabilities by preventing "
            "inserted scripts from being transmitted to users in an executable form. "
            "Applications can gain significant protection from javascript based attacks by converting the following "
            "characters in all generated output to the appropriate HTML entity encoding: "
            "<, >, &, ', (, ), #, %, ; , +, -"
        )

    @classmethod
    def short_name(cls) -> str:
        return "XSS"

    @classmethod
    def type(cls) -> str:
        return "vulnerability"

    @classmethod
    def wstg_code(cls) -> List[str]:
        return ["WSTG-INPV-01"]
