#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2008-2023 Nicolas Surribas
# Copyright (C) 2020-2024 Cyberwatch
#
# Original authors :
# Alberto Pastor
# David del Pozo
# Copyright (C) 2008 Informatica Gesfor
# ICT Romulus (http://www.ict-romulus.eu)
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
import time

from httpx import Response


class ReportGenerator:
    def __init__(self):
        self._infos = {}
        self._date = None

    def set_report_info(
        self,
        target: str,
        scope,
        date,
        version,
        auth,
        crawled_pages: list,
        crawled_pages_nbr: int,
        detailed_report_level: int
    ):
        """Set the information about the scan"""
        self._infos["target"] = target
        self._infos["date"] = time.strftime("%a, %d %b %Y %H:%M:%S +0000", date)
        self._infos["version"] = version
        self._infos["scope"] = scope
        self._infos["auth"] = auth
        self._infos["crawled_pages_nbr"] = crawled_pages_nbr
        if detailed_report_level in (1, 2):
            self._infos["crawled_pages"] = crawled_pages
        self._infos["detailed_report_level"] = detailed_report_level
        self._date = date

    @property
    def scan_date(self):
        return self._date

    def generate_report(self, output_path):
        raise NotImplementedError("Must be overridden")

    # Vulnerabilities
    def add_vulnerability_type(self, name: str, description: str = "", solution: str = "", references=None, wstg=None):
        raise NotImplementedError("Must be overridden")

    def add_vulnerability(
        self,
        module: str,
        category=None,
        level=0,
        request=None,
        parameter="",
        info="",
        wstg: str = None,
        response: Response = None
    ):
        raise NotImplementedError("Must be overridden")

    # Anomalies
    def add_anomaly_type(self, name, description="", solution="", references=None, wstg=None):
        raise NotImplementedError("Must be overridden")

    def add_anomaly(
        self,
        module: str,
        category=None,
        level=0,
        request=None,
        parameter="",
        info="",
        wstg=None,
        response: Response = None
    ):
        raise NotImplementedError("Must be overridden")

    # Additionals
    def add_additional_type(self, name, description="", solution="", references=None, wstg=None):
        raise NotImplementedError("Must be overridden")

    def add_additional(
        self,
        module: str,
        category=None,
        level=0,
        request=None,
        parameter="",
        info="",
        wstg=None,
        response: Response = None
    ):
        raise NotImplementedError("Must be overridden")
