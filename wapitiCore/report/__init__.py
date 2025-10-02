#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2021-2023 Nicolas Surribas
# Copyright (C) 2021-2024 Cyberwatch
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
from .reportgenerator import ReportGenerator
from .csvreportgenerator import CSVReportGenerator
from .htmlreportgenerator import HTMLReportGenerator
from .jsonreportgenerator import JSONReportGenerator
from .txtreportgenerator import TXTReportGenerator
from .xmlreportgenerator import XMLReportGenerator
from .nucleireportgenerator import NucleiReportGenerator

GENERATORS = {
    "csv": CSVReportGenerator,
    "html": HTMLReportGenerator,
    "json": JSONReportGenerator,
    "txt": TXTReportGenerator,
    "xml": XMLReportGenerator,
    "nuclei": NucleiReportGenerator
}


def get_report_generator_instance(report_format: str = "html"):
    return GENERATORS[report_format]()
