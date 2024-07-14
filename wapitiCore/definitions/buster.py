#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2023-2024 Cyberwatch
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
from typing import List

from wapitiCore.definitions.base import FindingBase


class BusterFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "Review Webserver Metafiles for Information Leakage"

    @classmethod
    def description(cls) -> str:
        return (
            "Test various metadata files for information leakage of the web application’s path(s), or functionality"
        )

    @classmethod
    def references(cls) -> list:
        return [
            {
                "title": "OWASP: Review Webserver Metafiles for Information Leakage",
                "url": (
                    "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/"
                    "01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage"
                )
            }
        ]

    @classmethod
    def solution(cls) -> str:
        return (
            "This is only for informational purposes."
        )

    @classmethod
    def short_name(cls) -> str:
        return cls.name()

    @classmethod
    def type(cls) -> str:
        return "additional"

    @classmethod
    def wstg_code(cls) -> List[str]:
        return ["WSTG-INFO-03"]
