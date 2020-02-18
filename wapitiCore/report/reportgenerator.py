#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (http://wapiti.sourceforge.io)
# Copyright (C) 2008-2020 Nicolas Surribas
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


class ReportGenerator:
    def __init__(self):
        self._infos = {}
        self._date = None

    def set_report_info(self, target, scope, date, version):
        """Set the informations about the scan"""
        self._infos["target"] = target
        self._infos["date"] = time.strftime("%a, %d %b %Y %H:%M:%S +0000", date)
        self._infos["version"] = version
        self._infos["scope"] = scope
        self._date = date

    @property
    def scan_date(self):
        return self._date

    def generate_report(self, output_path):
        pass

    # Vulnerabilities
    def add_vulnerability_type(self, name, description="", solution="", references=None):
        pass

    def add_vulnerability(self, category=None, level=0, request=None, parameter="", info=""):
        pass

    # Anomalies
    def add_anomaly_type(self, name, description="", solution="", references=None):
        pass

    def add_anomaly(self, category=None, level=0, request=None, parameter="", info=""):
        pass
