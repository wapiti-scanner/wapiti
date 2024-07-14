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
from typing import List, Dict

from wapitiCore.definitions.base import FindingBase


class ClickjackingFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "Clickjacking Protection"

    @classmethod
    def description(cls) -> str:
        return (
            "Clickjacking is a technique that tricks a user into clicking something different from what the user "
            "perceives, potentially revealing confidential information or taking control of their computer."
        )

    @classmethod
    def references(cls) -> List[Dict[str, str]]:
        return [
            {
                "title": "OWASP: Clickjacking",
                "url": (
                    "https://owasp.org/www-project-web-security-testing-guide/latest/"
                    "4-Web_Application_Security_Testing/11-Client-side_Testing/09-Testing_for_Clickjacking"
                )
            },
            {
                "title": "KeyCDN: Preventing Clickjacking",
                "url": "https://www.keycdn.com/support/prevent-clickjacking"
            }
        ]

    @classmethod
    def solution(cls) -> str:
        return "Implement X-Frame-Options or Content Security Policy (CSP) frame-ancestors directive."

    @classmethod
    def short_name(cls) -> str:
        return cls.name()

    @classmethod
    def type(cls) -> str:
        return "vulnerability"

    @classmethod
    def wstg_code(cls) -> List[str]:
        return ["OSHP-X-Frame-Options"]


class MimeTypeConfusionFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "MIME Type Confusion"

    @classmethod
    def description(cls) -> str:
        return (
            "MIME type confusion can occur when a browser interprets files as a different type than intended, "
            "which could lead to security vulnerabilities like cross-site scripting (XSS)."
        )

    @classmethod
    def references(cls) -> List[Dict[str, str]]:
        return [
            {
                "title": "OWASP: MIME Sniffing",
                "url": "https://owasp.org/www-community/attacks/MIME_sniffing"
            },
            {
                "title": "KeyCDN: Preventing MIME Type Sniffing",
                "url": "https://www.keycdn.com/support/preventing-mime-type-sniffing"
            }
        ]

    @classmethod
    def solution(cls) -> str:
        return "Implement X-Content-Type-Options to prevent MIME type sniffing."

    @classmethod
    def short_name(cls) -> str:
        return cls.name()

    @classmethod
    def type(cls) -> str:
        return "vulnerability"

    @classmethod
    def wstg_code(cls) -> List[str]:
        return ["OSHP-X-Content-Type-Options"]


class HstsFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "HTTP Strict Transport Security (HSTS)"

    @classmethod
    def description(cls) -> str:
        return (
            "HSTS is a web security policy mechanism that helps to protect websites against man-in-the-middle attacks "
            "such as protocol downgrade attacks and cookie hijacking."
        )

    @classmethod
    def references(cls) -> List[Dict[str, str]]:
        return [
            {
                "title": "OWASP: HTTP Strict Transport Security",
                "url":
                    (
                        "https://owasp.org/www-project-web-security-testing-guide/latest/"
                        "4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/"
                        "07-Test_HTTP_Strict_Transport_Security"
                    )
            },
            {
                "title": "KeyCDN: Enabling HSTS",
                "url": "https://www.keycdn.com/support/hsts"
            }
        ]

    @classmethod
    def solution(cls) -> str:
        return "Implement the HTTP Strict Transport Security header to enforce secure connections to the server."

    @classmethod
    def short_name(cls) -> str:
        return cls.name()

    @classmethod
    def type(cls) -> str:
        return "vulnerability"

    @classmethod
    def wstg_code(cls) -> List[str]:
        return ["WSTG-CONF-07", "OSHP-HTTP-Strict-Transport-Security"]
