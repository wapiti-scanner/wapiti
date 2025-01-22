#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2025 Cyberwatch
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


class FortiAuthenticationBypass(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "CVE-2024-55591"

    @classmethod
    def description(cls) -> str:
        return (
            "An Authentication Bypass Using an Alternate Path or Channel vulnerability [CWE-288] affecting FortiOS \
            version 7.0.0 through 7.0.16 and FortiProxy version 7.0.0 through 7.0.19 and 7.2.0 through 7.2.12 ."
        ) + " " + (
            "The vulnerability allows a remote attacker to gain super-admin privileges via crafted requests \
             to Node.js websocket module."
        )

    @classmethod
    def references(cls) -> list:
        return [
            {
                "title": "CWE-288: Authentication Bypass Using an Alternate Path or Channel",
                "url": (
                    "https://cwe.mitre.org/data/definitions/288.html"
                )
            },
        ]

    @classmethod
    def solution(cls) -> str:
        return (
            "Upgrade FortiOS 7.0 to 7.0.17 or above ."
        ) + " " + (
            "Upgrade FortiProxy 7.0 to 7.0.20 or above."
        ) + " " + (
            "Upgrade FortiProxy 7.2 to 7.2.13 or above"
        )

    @classmethod
    def short_name(cls) -> str:
        return cls.name()

    @classmethod
    def type(cls) -> str:
        return "vulnerability"

    @classmethod
    def wstg_code(cls) -> List[str]:
        return ["WSTG-ATHN-04", "WSTG-INPV-12"]
