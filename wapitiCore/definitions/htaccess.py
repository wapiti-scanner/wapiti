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

NAME = _("Htaccess Bypass")
SHORT_NAME = NAME

DESCRIPTION = _(
    "Htaccess files are used to restrict access to some files or HTTP method."
) + " " + _(
    "In some case it may be possible to bypass this restriction and access the files."
)

SOLUTION = _(
    "Make sure every HTTP method is forbidden if the credentials are bad."
)

REFERENCES = [
    {
        "title": "A common Apache .htaccess misconfiguration",
        "url": "http://blog.teusink.net/2009/07/common-apache-htaccess-misconfiguration.html"
    },
    {
        "title": "CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory",
        "url": "https://cwe.mitre.org/data/definitions/538.html"
    },
]
