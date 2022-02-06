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

NAME = _("Internal Server Error")
SHORT_NAME = NAME

WSTG_CODE = ["WSTG-ERRH-01"]

DESCRIPTION = _(
    "An error occurred on the server's side, preventing it to process the request."
) + " " + _(
    "It may be the sign of a vulnerability."
)

SOLUTION = _(
    "More information about the error should be found in the server logs."
)

REFERENCES = [
    {
        "title": "Wikipedia: List of 5xx HTTP status codes",
        "url": "https://en.wikipedia.org/wiki/List_of_HTTP_status_codes#5xx_Server_Error"
    },
    {
        "title": "OWASP: Improper Error Handling",
        "url": "https://owasp.org/www-community/Improper_Error_Handling"
    },
    {
        "title": "OWASP: Improper Error Handling",
        "url": (
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/"
            "08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling"
        )
    }
]
