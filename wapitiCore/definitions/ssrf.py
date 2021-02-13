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

NAME = _("Server Side Request Forgery")
SHORT_NAME = _("SSRF")

DESCRIPTION = _(
    "The target application may have functionality for importing data from a URL, "
    "publishing data to a URL or otherwise reading data from a URL that can be tampered with."
)

SOLUTION = _(
    "Every URI received by the web application should be checked, "
    "especially scheme and hostname. A whitelist should be used."
)

REFERENCES = [
    {
        "title": "OWASP: Server Side Request Forgery",
        "url": "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"
    },
    {
        "title": "Acunetix: What is Server Side Request Forgery (SSRF)?",
        "url": "https://www.acunetix.com/blog/articles/server-side-request-forgery-vulnerability/"
    },
    {
        "title": "What is the Server Side Request Forgery Vulnerability & How to Prevent It?",
        "url": "https://www.netsparker.com/blog/web-security/server-side-request-forgery-vulnerability-ssrf/"
    },
    {
        "title": "CWE-918: Server-Side Request Forgery (SSRF)",
        "url": "https://cwe.mitre.org/data/definitions/918.html"
    },
]
