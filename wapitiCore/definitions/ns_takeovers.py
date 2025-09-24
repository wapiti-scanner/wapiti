#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2025 Nicolas Surribas
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


class NSTakeoverFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "NS takeover"

    @classmethod
    def description(cls) -> str:
        return (
            "A DNS NS record points to a non existing domain that an attacker can take control of, "
            "allowing them to hijack the entire DNS zone."
        )

    @classmethod
    def references(cls) -> list:
        return [
            {
                "title": "Subdomain Takeover: Going beyond CNAME",
                "url": "https://0xpatrik.com/subdomain-takeover-ns/"
            },
            {
                "title": "A Guide to DNS Takeovers: The Misunderstood Cousin of Subdomain Takeovers",
                "url": "https://projectdiscovery.io/blog/guide-to-dns-takeovers"
            },
            {
                "title": "MasterCard DNS Error Went Unnoticed for Years",
                "url": "https://krebsonsecurity.com/2025/01/mastercard-dns-error-went-unnoticed-for-years/"
            }
        ]

    @classmethod
    def solution(cls) -> str:
        return (
            "Prevent dangling DNS entries by making sure you already have control over the pointed domain. "
            "Remove any NS record pointing to an external domain you don't use."
        )

    @classmethod
    def short_name(cls) -> str:
        return cls.name()

    @classmethod
    def type(cls) -> str:
        return "vulnerability"

    @classmethod
    def wstg_code(cls) -> List[str]:
        # WSTG-CONF-10 is for subdomain takeover, no specific code for NS takeover exists yet in WSTG
        return ["WSTG-CONF-10"]
