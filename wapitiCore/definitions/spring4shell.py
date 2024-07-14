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


class Spring4ShellFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "Spring4Shell"

    @classmethod
    def description(cls) -> str:
        return (
            "A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution "
            "(RCE) via data binding. "
            "The specific exploit requires the application to run on Tomcat as a WAR deployment."
            "If the application is deployed as a Spring Boot executable jar, i.e. the default,"
            "it is not vulnerable to the exploit. However, the nature of the vulnerability is more general,"
            "and there may be other ways to exploit it."
        )

    @classmethod
    def references(cls) -> list:
        return [
            {
                "title": "CYBERWATCH: Spring4Shell CVE-2022-22965",
                "url": (
                    "https://cyberwatch.fr/cve/spring4shell-tout-savoir-sur-la-vulnerabilite-0-day-liee-a-java-spring/"
                )
            },
            {
                "title": "VMWARE: CVE-2022-22965 Detail",
                "url": "https://tanzu.vmware.com/security/cve-2022-22965"
            },
            {
                "title": "MITRE: CVE-2022-22965",
                "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965"
            },
            {
                "title": "OWASP: Code Injection",
                "url": (
                    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/"
                    "07-Input_Validation_Testing/11-Testing_for_Code_Injection"
                )
            }
        ]

    @classmethod
    def solution(cls) -> str:
        return (
            "Users of affected versions should apply the following mitigation: 5.3.x users should upgrade to 5.3.18+,"
            "5.2.x users should upgrade to 5.2.20+. No other steps are necessary."
            "There are other mitigation steps for applications that cannot upgrade to the above versions."
        )

    @classmethod
    def short_name(cls) -> str:
        return cls.name()

    @classmethod
    def type(cls) -> str:
        return "vulnerability"

    @classmethod
    def wstg_code(cls) -> List[str]:
        return ["WSTG-INPV-11"]
