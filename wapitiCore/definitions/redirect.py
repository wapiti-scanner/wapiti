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


class RedirectFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "Open Redirect"

    @classmethod
    def description(cls) -> str:
        return (
            "Unvalidated redirects and forwards are possible when a web application accepts untrusted input that could "
            "cause the web application to redirect the request to a URL contained within untrusted input. "
            "By modifying untrusted URL input to a malicious site, "
            "an attacker may successfully launch a phishing scam and steal user credentials."
        )

    @classmethod
    def references(cls) -> list:
        return [
            {
                "title": "Unvalidated Redirects and Forwards Cheat Sheet",
                "url": (
                    "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"
                )
            },
            {
                "title": "Acunetix: What Are Open Redirects?",
                "url": "https://www.acunetix.com/blog/web-security-zone/what-are-open-redirects/"
            },
            {
                "title": "CWE-601: URL Redirection to Untrusted Site ('Open Redirect')",
                "url": "https://cwe.mitre.org/data/definitions/601.html"
            },
            {
                "title": "OWASP: Client-side URL Redirect",
                "url": (
                    "https://owasp.org/www-project-web-security-testing-guide/latest/"
                    "4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect"
                )
            }
        ]

    @classmethod
    def solution(cls) -> str:
        return (
            "Force all redirects to first go through a page notifying users that they are going off of your site, "
            "and have them click a link to confirm."
        )

    @classmethod
    def short_name(cls) -> str:
        return cls.name()

    @classmethod
    def type(cls) -> str:
        return "vulnerability"

    @classmethod
    def wstg_code(cls) -> List[str]:
        return ["WSTG-CLNT-04"]
