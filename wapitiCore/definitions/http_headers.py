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

NAME = _("HTTP Secure Headers")
SHORT_NAME = NAME

WSTG_CODE_FRAME_OPTIONS = ["WSTG-CLNT-09"]
WSTG_CODE_XSS_PROTECTION = ["WSTG-INPV-01", "WSTG-INPV-02"]
WSTG_CODE_CONTENT_TYPE_OPTIONS = ["WSTG-ATHN-01"]
WSTG_CODE_STRICT_TRANSPORT_SECURITY = ["WSTG-CONF-07"]

WSTG_CODE = (
    WSTG_CODE_FRAME_OPTIONS +
    WSTG_CODE_XSS_PROTECTION +
    WSTG_CODE_CONTENT_TYPE_OPTIONS +
    WSTG_CODE_STRICT_TRANSPORT_SECURITY
)

DESCRIPTION = _(
    "HTTP security headers tell the browser how to behave when handling the website's content."
)

SOLUTION = _(
    "Use the recommendations for hardening your HTTP Security Headers."
)

REFERENCES = [
    {
        "title": "Netsparker: HTTP Security Headers: An Easy Way to Harden Your Web Applications",
        "url": "https://www.netsparker.com/blog/web-security/http-security-headers/"
    },
    {
        "title": "KeyCDN: Hardening Your HTTP Security Headers",
        "url": "https://www.keycdn.com/blog/http-security-headers"
    },
    {
        "title": "OWASP: HTTP SECURITY HEADERS (Protection For Browsers) (PDF)",
        "url": "https://owasp.org/www-chapter-ghana/assets/slides/HTTP_Header_Security.pdf"
    },
    {
        "title": "OWASP: Clickjacking",
        "url": (
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/"
            "11-Client-side_Testing/09-Testing_for_Clickjacking"
        )
    },
    {
        "title": "OWASP: Reflected Cross Site Scripting",
        "url": (
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/"
            "07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting"
        )
    },
    {
        "title": "OWASP: Stored Cross Site Scripting",
        "url": (
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/"
            "07-Input_Validation_Testing/02-Testing_for_Stored_Cross_Site_Scripting"
        )
    },
    {
        "title": "OWASP: HTTP Strict Transport Security",
        "url": (
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/"
            "02-Configuration_and_Deployment_Management_Testing/07-Test_HTTP_Strict_Transport_Security"
        )
    }
]
