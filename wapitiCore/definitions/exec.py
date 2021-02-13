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

NAME = _("Command execution")
SHORT_NAME = NAME

DESCRIPTION = _(
    "This attack consists in executing system commands on the server."
) + " " + _(
    "The attacker tries to inject this commands in the request parameters."
)

SOLUTION = _(
    "Prefer working without user input when using file system calls."
)

REFERENCES = [
    {
        "title": "OWASP: Command Injection",
        "url": "https://owasp.org/www-community/attacks/Command_Injection"
    },
    {
        "title": "CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        "url": "https://cwe.mitre.org/data/definitions/78.html"
    },
]
