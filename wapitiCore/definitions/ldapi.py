#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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

NAME = "LDAP Injection"
SHORT_NAME = "LDAPI"

WSTG_CODE = ["WSTG-INPV-06"]

DESCRIPTION = (
    "LDAP Injection is an attack used to exploit web based applications that construct LDAP statements based on "
    "user input."
) + " " + (
    "When an application fails to properly sanitize user input, it’s possible to modify LDAP statements using "
    "a local proxy."
) + " " + (
    "This could result in the execution of arbitrary commands such as granting permissions to unauthorized queries."
)

SOLUTION = (
    "To protect against XPATH injection, Escape all variables using the right LDAP encoding function."
) + " " + (
    "Use Frameworks that Automatically Protect from LDAP Injection."
)

REFERENCES = [
    {
        "title": "LDAP Injection",
        "url": "https://owasp.org/www-community/attacks/LDAP_Injection"
    },
    {
        "title": "LDAP Injection Prevention Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html"
    },
    {
        "title": "CWE-90: Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')",
        "url": "https://cwe.mitre.org/data/definitions/90.html"
    }
]
