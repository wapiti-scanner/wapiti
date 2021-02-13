#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of the Wapiti project (https://wapiti.sourceforge.io)
# Copyright (C) 2021 Nicolas Surribas
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
from wapitiCore.language.language import _

TYPE = "vulnerability"

NAME = _("SQL Injection")
SHORT_NAME = _("SQLI")

DESCRIPTION = _(
    "SQL injection vulnerabilities allow an attacker to alter the queries executed on the backend database."
) + " " + _(
    "An attacker may then be able to extract or modify information stored in the database or even escalate his "
    "privileges on the system."
)

SOLUTION = _(
    "To protect against SQL injection, user input must not directly be embedded in SQL statements."
) + " " + _(
    "Instead, user input must be escaped or filtered or parameterized statements must be used."
)

REFERENCES = [
    {
        "title": "OWASP: SQL Injection",
        "url": "https://owasp.org/www-community/attacks/SQL_Injection"
    },
    {
        "title": "Wikipedia: SQL injection",
        "url": "https://en.wikipedia.org/wiki/SQL_injection"
    },
    {
        "title": "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        "url": "https://cwe.mitre.org/data/definitions/89.html"
    },
]
