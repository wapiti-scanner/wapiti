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

NAME = _("Weak credentials")
SHORT_NAME = NAME

DESCRIPTION = _(
    "The web application is using either default credentials or weak passwords that can be found in well-known "
    "passwords lists."
)

SOLUTION = _(
    "Do not ship or deploy with any default credentials, particularly for admin users."
) + " " + _(
    "Implement weak-password checks, such as testing new or changed passwords "
    "against a list of the top 10000 worst passwords."
)

REFERENCES = [
    {
        "title": "CWE-798: Use of Hard-coded Credentials",
        "url": "https://cwe.mitre.org/data/definitions/798.html"
    },
    {
        "title": "CWE-521: Weak Password Requirements",
        "url": "https://cwe.mitre.org/data/definitions/521.html"
    },
]
