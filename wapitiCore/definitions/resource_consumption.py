#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2021-2022 Nicolas Surribas
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

TYPE = "anomaly"

NAME = _("Resource consumption")
SHORT_NAME = NAME

WSTG_CODE = ["WSTG-ERRH-01"]

DESCRIPTION = _(
    "It took an abnormal time to the server to respond to a query."
) + " " + _(
    "An attacker might leverage this kind of weakness to overload the server."
)

SOLUTION = _(
    "The involved script is maybe using the server resources (CPU, memory, network, file access...) "
    "in a non-efficient way."
)

REFERENCES = [
    {
        "title": "CWE-405: Asymmetric Resource Consumption (Amplification)",
        "url": "https://cwe.mitre.org/data/definitions/405.html"
    },
    {
        "title": "CWE-400: Uncontrolled Resource Consumption",
        "url": "https://cwe.mitre.org/data/definitions/400.html"
    },
    {
        "title": "OWASP: Improper Error Handling",
        "url": (
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/"
            "08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling"
        )
    }
]
