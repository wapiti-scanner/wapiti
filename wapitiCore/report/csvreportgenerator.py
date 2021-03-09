#!/usr/bin/env python3

# CSV Report Generator Module for Wapiti Project
# Wapiti Project (https://wapiti.sourceforge.io)
#
# Copyright (C) 2021 Nicolas SURRIBAS
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
import csv

from wapitiCore.report.reportgenerator import ReportGenerator


class CSVReportGenerator(ReportGenerator):
    """This class allow generating reports in CSV format.
    """

    def __init__(self):
        super().__init__()
        self._vulns = []
        self._anomalies = []
        self._additionals = []

    def generate_report(self, output_path):
        """
        Generate a CSV report of the vulnerabilities, anomalies and additionals which have
        been previously logged with the log* methods.
        """
        with open(output_path, 'w', newline='', encoding="utf-8") as csv_fd:
            writer = csv.writer(csv_fd, quoting=csv.QUOTE_NONNUMERIC, doublequote=False, escapechar="\\")
            writer.writerow(["category", "level", "description", "method", "parameter", "url", "body"])
            writer.writerows(self._vulns)
            writer.writerows(self._anomalies)
            writer.writerows(self._additionals)

    def add_vulnerability(self, category=None, level=0, request=None, parameter="", info=""):
        """
        Store the information about a vulnerability.
        """
        if request is not None:
            self._vulns.append(
                [category, level, info, request.method, parameter, request.url, request.encoded_data]
            )

    def add_anomaly(self, category=None, level=0, request=None, parameter="", info=""):
        """Store the information about an anomaly met during the attack."""
        if request is not None:
            self._anomalies.append(
                [category, level, info, request.method, parameter, request.url, request.encoded_data]
            )

    def add_additional(self, category=None, level=0, request=None, parameter="", info=""):
        """Store the information about an additional."""
        if request is not None:
            self._additionals.append(
                [category, level, info, request.method, parameter, request.url, request.encoded_data]
            )

    # We don't want description of each vulnerability for this report format
    def add_vulnerability_type(self, name, description="", solution="", references=None):
        pass

    def add_anomaly_type(self, name, description="", solution="", references=None):
        pass

    def add_additional_type(self, name, description="", solution="", references=None):
        pass
