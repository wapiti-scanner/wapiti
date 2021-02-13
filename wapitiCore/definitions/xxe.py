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

NAME = _("XML External Entity")
SHORT_NAME = _("XXE")

DESCRIPTION = _(
    "An XML External Entity attack is a type of attack against an application that parses XML input."
) + " " + _(
    "This attack occurs when XML input containing a reference to an external entity is processed by a weakly "
    "configured XML parser."
) + " " + _(
    "This attack may lead to the disclosure of confidential data, denial of service, server side request forgery, "
    "port scanning from the perspective of the machine where the parser is located, and other system impacts."
)

SOLUTION = _("The safest way to prevent XXE is always to disable DTDs (External Entities) completely.")

REFERENCES = [
    {
        "title": "OWASP: XML External Entity (XXE) Processing",
        "url": "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing"
    },
    {
        "title": "PortSwigger: What is XML external entity injection?",
        "url": "https://portswigger.net/web-security/xxe"
    },
    {
        "title": "CWE-611: Improper Restriction of XML External Entity Reference",
        "url": "https://cwe.mitre.org/data/definitions/611.html"
    },
    {
        "title": "OWASP: XML External Entity Prevention Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html"
    },
]
