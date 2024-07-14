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


class SslInformationFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "TLS/SSL misconfigurations"

    @classmethod
    def description(cls) -> str:
        return (
            "The TLS protocol aims primarily to provide privacy and data integrity between "
            "two or more communicating computer applications."
        ) + " " + (
            "Over the years numerous vulnerabilities have been discovered in some SSL/TLS version or specific ciphers "
            "making the integrity of the communications at risk (eavesdropping, alteration...)"
        )

    @classmethod
    def references(cls) -> list:
        return [
            {
                "title": "SSL Labs: SSL and TLS Deployment Best Practices",
                "url": "https://github.com/ssllabs/research/wiki/SSL-and-TLS-Deployment-Best-Practices"
            },
            {
                "title": "Mozilla: Server Side TLS recommended configurations",
                "url": "https://wiki.mozilla.org/Security/Server_Side_TLS"
            },
            {
                "title": "Beagle Security: Importance of TLS 1.3, SSL and TLS Vulnerabilities",
                "url": "https://beaglesecurity.com/blog/article/importance-of-tls-1-3-ssl-and-tls-vulnerabilities.html"
            },
            {
                "title": "Security of TLS cipher suites",
                "url": "https://ciphersuite.info/"
            },
            {
                "title": "Trail of Bits: What Application Developers Need To Know About TLS Early Data (0RTT)",
                "url": (
                    "https://blog.trailofbits.com/2019/03/25/"
                    "what-application-developers-need-to-know-about-tls-early-data-0rtt/"
                )
            },
            {
                "title": "OWASP: Weak SSL TLS Ciphers Insufficient Transport Layer Protection",
                "url": (
                    "https://owasp.org/www-project-web-security-testing-guide/v41/"
                    "4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/"
                    "01-Testing_for_Weak_SSL_TLS_Ciphers_Insufficient_Transport_Layer_Protection"
                )
            }
        ]

    @classmethod
    def solution(cls) -> str:
        return (
            "To protect against SSL/TLS vulnerabilities, make sure that deprecated versions of the protocol "
            "are disabled."
        ) + " " + (
            "Refer to up-to-date recommendations to only allow modern versions of TLS with Perfect Forward Secrecy."
        )

    @classmethod
    def short_name(cls) -> str:
        return "SSL misconfigurations"

    @classmethod
    def type(cls) -> str:
        return "additional"

    @classmethod
    def wstg_code(cls) -> List[str]:
        return ["WSTG-CRYP-01"]


LEVELS = [
    # For translation purpose only
    "Insecure",
    "Weak",
    "Secure",
    "Recommended",
    "Unknown",
]


class SslVulnerabilityFinding(SslInformationFinding):
    @classmethod
    def type(cls) -> str:
        return "vulnerability"
