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

NAME = _("HttpOnly Flag cookie")
SHORT_NAME = NAME

DESCRIPTION = _(
    "HttpOnly is an additional flag included in a Set-Cookie HTTP response header."
) + " " + _(
    "Using the HttpOnly flag when generating a cookie helps mitigate the risk of client side script accessing "
    "the protected cookie (if the browser supports it)."
)

SOLUTION = _(
    "While creation of the cookie, make sure to set the HttpOnly Flag to True."
)

REFERENCES = [
    {
        "title": "OWASP: Testing for Cookies Attributes",
        "url": (
            "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/"
            "06-Session_Management_Testing/02-Testing_for_Cookies_Attributes.html"
        )
    },
    {
        "title": "OWASP: HttpOnly",
        "url": "https://owasp.org/www-community/HttpOnly"
    }
]
