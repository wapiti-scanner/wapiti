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

TYPE = "vulnerability"

NAME = _("Content Security Policy Configuration")
SHORT_NAME = _("CSP Configuration")

WSTG_CODE = ["WSTG-CONF-01", "WSTG-CONF-12"]

DESCRIPTION = _(
    "Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types "
    "of attacks, including Cross Site Scripting (XSS) and data injection attacks."
)

SOLUTION = _(
    "Configuring Content Security Policy involves adding the Content-Security-Policy HTTP header to a web page and "
    "giving it values to control what resources the user agent is allowed to load for that page."
)

REFERENCES = [
    {
        "title": "Mozilla: Content Security Policy (CSP)",
        "url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP"
    },
    {
        "title": "OWASP: Content Security Policy Cheat Sheet",
        "url": (
            "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html"
        )
    },
    {
        "title": "OWASP: How to do Content Security Policy (PDF)",
        "url": (
            "https://owasp.org/www-pdf-archive/2019-02-22_-_How_do_I_Content_Security_Policy_-_Print.pdf"
        )
    },
    {
        "title": "OWASP: Network Infrastructure Configuration",
        "url": (
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/"
            "02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration"
        )
    },
    {
        "title": "OWASP: Content Security Policy",
        "url": (
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/"
            "02-Configuration_and_Deployment_Management_Testing/12-Test_for_Content_Security_Policy"
        )
    }
]
