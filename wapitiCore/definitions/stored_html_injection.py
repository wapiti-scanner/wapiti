#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2023-2024 Nicolas Surribas
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


class StoredHtmlFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "Stored HTML Injection"

    @classmethod
    def description(cls) -> str:
        return (
            "HTML injection is a type of injection vulnerability that occurs when a user is able to control an input "
            "point and is able to inject arbitrary HTML code into a vulnerable web page. "
            "This vulnerability can allow the attacker to modify the page content seen by the victims."
        )

    @classmethod
    def references(cls) -> list:
        return [
            {
                "title": "OWASP: Testing for HTML Injection",
                "url": (
                    "https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/"
                    "11-Client_Side_Testing/03-Testing_for_HTML_Injection"
                )
            },
            {
                "title": "IMPERVA: HTML Injection",
                "url": "https://www.imperva.com/learn/application-security/html-injection/",
            },
            {
                "title": "HackTricks: Dangling Markup - HTML scriptless injection",
                "url": "https://book.hacktricks.xyz/pentesting-web/dangling-markup-html-scriptless-injection"
            },
        ]

    @classmethod
    def solution(cls) -> str:
        return (
            "Avoid Raw HTML Rendering: Whenever possible, avoid directly rendering user-generated content as raw HTML. "
            "Instead, use built-in templating systems or libraries that automatically escape user input by default, "
            "such as Django's template engine or AngularJS's ng-bind directive. "
            "With PHP you can use the htmlspecialchars() function to convert special characters to their corresponding "
            "HTML entities."
        )

    @classmethod
    def short_name(cls) -> str:
        return cls.name()

    @classmethod
    def type(cls) -> str:
        return "vulnerability"

    @classmethod
    def wstg_code(cls) -> List[str]:
        return ["WSTG-CLNT-03"]
