#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2023 Nicolas Surribas
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
TYPE = "vulnerability"

NAME = "Unrestricted File Upload"
SHORT_NAME = "Unrestricted Upload"

WSTG_CODE = ["WSTG-BUSL-08"]
# CWE-434: Unrestricted Upload of File with Dangerous Type

DESCRIPTION = (
    "File upload vulnerabilities are when a web server allows users to upload files to its filesystem without "
    "sufficiently validating things like their name, type, contents, or size. Failing to properly enforce "
    "restrictions on these could allow an attacker to upload potentially dangerous files. This could even include "
    "server-side script files that enable remote code execution."
)

SOLUTION = (
    "Check the file extension against a whitelist of permitted extensions rather than a blacklist of prohibited ones. "
    "Make sure the filename doesn't contain any substrings that may be interpreted as a directory or a traversal "
    "sequence (../). "
    "Rename uploaded files to avoid collisions that may cause existing files to be overwritten. "
    "Do not upload files to the server's permanent filesystem until they have been fully validated."
)

REFERENCES = [
    {
        "title": "HackTricks: File Upload",
        "url": "https://book.hacktricks.xyz/pentesting-web/file-upload"
    },
    {
        "title": "PortSwigger : File upload vulnerabilities",
        "url": "https://portswigger.net/web-security/file-upload"
    },
    {
        "title": "CWE-434: Unrestricted Upload of File with Dangerous Type",
        "url": "https://cwe.mitre.org/data/definitions/434.html"
    },
    {
        "title": "OWASP: Test Upload of Unexpected File Types",
        "url": (
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/"
            "10-Business_Logic_Testing/08-Test_Upload_of_Unexpected_File_Types"
        )
    }
]
