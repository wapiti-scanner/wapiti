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

NAME = _("Open Redirect")
SHORT_NAME = NAME

DESCRIPTION = _(
    "Unvalidated redirects and forwards are possible when a web application accepts untrusted input that could cause "
    "the web application to redirect the request to a URL contained within untrusted input."
) + " " + _(
    "By modifying untrusted URL input to a malicious site, "
    "an attacker may successfully launch a phishing scam and steal user credentials."
)

SOLUTION = _(
    "Force all redirects to first go through a page notifying users that they are going off of your site, "
    "and have them click a link to confirm."
)

REFERENCES = [
    {
        "title": "Unvalidated Redirects and Forwards Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"
    },
    {
        "title": "Acunetix: What Are Open Redirects?",
        "url": "https://www.acunetix.com/blog/web-security-zone/what-are-open-redirects/"
    },
    {
        "title": "CWE-601: URL Redirection to Untrusted Site ('Open Redirect')",
        "url": "https://cwe.mitre.org/data/definitions/601.html"
    },
]
