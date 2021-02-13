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

NAME = _("Path Traversal")
SHORT_NAME = NAME

DESCRIPTION = _(
    "This attack is known as Path or Directory Traversal."
) + " " + _(
    "Its aim is the access to files and directories that are stored outside the web root folder."
) + " " + _(
    "The attacker tries to explore the directories stored in the web server."
) + " " + (
    "The attacker uses some techniques, for instance, the manipulation of variables that reference files with "
    "'dot-dot-slash (../)' sequences and its variations to move up to root directory to navigate through "
    "the file system."
)

SOLUTION = _(
    "Prefer working without user input when using file system calls."
) + " " + _(
    "Use indexes rather than actual portions of file names when templating or using language files "
    "(eg: value 5 from the user submission = Czechoslovakian, rather than expecting the user to return "
    "'Czechoslovakian')."
) + " " + _(
    "Ensure the user cannot supply all parts of the path - surround it with your path code."
) + " " + _(
    "Validate the user's input by only accepting known good - do not sanitize the data."
) + " " + _(
    "Use chrooted jails and code access policies to restrict where the files can be obtained or saved to."
)

REFERENCES = [
    {
        "title": "OWASP: Path Traversal",
        "url": "https://owasp.org/www-community/attacks/Path_Traversal"
    },
    {
        "title": "Acunetix: What is a Directory Traversal attack?",
        "url": "https://www.acunetix.com/websitesecurity/directory-traversal/"
    },
    {
        "title": "CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
        "url": "https://cwe.mitre.org/data/definitions/22.html"
    },
]
