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
TYPE = "vulnerability"

NAME = "Log4Shell"
SHORT_NAME = NAME

WSTG_CODE = ["WSTG-INPV-11"]

DESCRIPTION = (
    "Apache Log4j2 <=2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against "
    "attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages "
    "or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution "
    "is enabled."
)

SOLUTION = (
    "From log4j 2.15.0, this behavior has been disabled by default. "
    "In previous releases (>2.10) this behavior can be mitigated "
    "by setting system property \"log4j2.formatMsgNoLookups\" to \"true\" "
    "or it can be mitigated in prior releases (<2.10) by removing the JndiLookup class "
    "from the classpath (example: zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class)."
)

REFERENCES = [
    {
        "title": "NVD: CVE-2021-44228 Detail",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
    },
    {
        "title": "NITRE: CVE-2021-44228",
        "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228"
    },
    {
        "title": "OWASP: Code Injection",
        "url": (
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/"
            "07-Input_Validation_Testing/11-Testing_for_Code_Injection"
        )
    }
]
