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

NAME = _("Blind SQL Injection")
SHORT_NAME = _("Blind SQLI")

DESCRIPTION = _(
    "Blind SQL injection is a technique that exploits a vulnerability occurring in the database of an application."
) + " " + _(
    "This kind of vulnerability is harder to detect than basic SQL injections because no error message will be "
    "displayed on the webpage."
)


SOLUTION = _(
    "To protect against SQL injection, user input must not directly be embedded in SQL statements."
) + " " + _(
    "Instead, user input must be escaped or filtered or parameterized statements must be used."
)

REFERENCES = [
    {
        "title": "OWASP: Blind SQL Injection",
        "url": "https://owasp.org/www-community/attacks/Blind_SQL_Injection"
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
