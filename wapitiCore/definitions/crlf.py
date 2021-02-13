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

NAME = _("CRLF Injection")
SHORT_NAME = NAME

DESCRIPTION = _(
    "The term CRLF refers to Carriage Return (ASCII 13, \\r) Line Feed (ASCII 10, \\n)."
) + " " + _(
    "A CRLF Injection attack occurs when a user manages to submit a CRLF into an application."
) + " " + _(
    "This is most commonly done by modifying an HTTP parameter or URL."
)

SOLUTION = _(
    "Check the submitted parameters and do not allow CRLF to be injected when it is not expected."
)

REFERENCES = [
    {
        "title": "OWASP: CRLF Injection",
        "url": "https://owasp.org/www-community/vulnerabilities/CRLF_Injection"
    },
    {
        "title": "Acunetix: What Are CRLF Injection Attacks",
        "url": "https://www.acunetix.com/websitesecurity/crlf-injection/"
    },
    {
        "title": "CWE-93: Improper Neutralization of CRLF Sequences ('CRLF Injection')",
        "url": "https://cwe.mitre.org/data/definitions/93.html"
    },
]
