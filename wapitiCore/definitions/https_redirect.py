#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2023-2024 Cyberwatch
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


class HstsFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "Unencrypted Channels"

    @classmethod
    def description(cls) -> str:
        return (
            "Sensitive data must be protected when it is transmitted through the network."
        )

    @classmethod
    def references(cls) -> list:
        return [
            {
                "title": "Testing for Sensitive Information Sent via Unencrypted Channels",
                "url": (
                    "https://owasp.org/www-project-web-security-testing-guide/latest/"
                    "4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/"
                    "03-Testing_for_Sensitive_Information_Sent_via_Unencrypted_Channels"
                )
            },
            {
                "title": "Testing for Weak Transport Layer Security",
                "url": (
                    "https://owasp.org/www-project-web-security-testing-guide/latest/"
                    "4-Web_Application_Security_Testing/"
                    "09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security"
                )
            }
        ]

    @classmethod
    def solution(cls) -> str:
        return "Use HTTPS for the whole web site and redirect any HTTP requests to HTTPS."

    @classmethod
    def short_name(cls) -> str:
        return cls.name()

    @classmethod
    def type(cls) -> str:
        return "vulnerability"

    @classmethod
    def wstg_code(cls) -> List[str]:
        return ["WSTG-CRYP-03"]
