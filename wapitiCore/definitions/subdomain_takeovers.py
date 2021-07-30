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

NAME = _("Subdomain takeover")
SHORT_NAME = NAME

DESCRIPTION = _(
    "A DNS CNAME record points to a non existing domain or to a content that an attacker can take control of."
)

SOLUTION = _(
    "Prevent dangling DNS entries by making sure you already have control over the pointed domain."
)

REFERENCES = [
    {
        "title": "Microsoft: Prevent dangling DNS entries and avoid subdomain takeover",
        "url": "https://docs.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover"
    },
    {
        "title": "Can I take over XYZ? — a list of services and how to claim (sub)domains with dangling DNS records.",
        "url": "https://github.com/EdOverflow/can-i-take-over-xyz"
    }
]
