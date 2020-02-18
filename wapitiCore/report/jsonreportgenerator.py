#!/usr/bin/env python3

# JSON Report Generator Module for Wapiti Project
# Wapiti Project (http://wapiti.sourceforge.io)
#
# Copyright (C) 2014-2020 Nicolas SURRIBAS
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
import json

from wapitiCore.report.reportgenerator import ReportGenerator


class JSONReportGenerator(ReportGenerator):
    """This class allow generating reports in JSON format.
    The root dictionary contains 4 dictionaries :
    - classifications : contains the description and references of a vulnerability type.
    - vulnerabilities : each key is matching a vulnerability class. Value is a list of found vulnerabilities.
    - anomalies : same as vulnerabilities but used only for error messages and timeouts (items of less importance).
    - infos : several informations about the scan.
    """

    def __init__(self):
        super().__init__()
        # Use only one dict for vulnerability and anomaly types
        self._flaw_types = {}

        self._vulns = {}
        self._anomalies = {}

    def generate_report(self, output_path):
        """
        Generate a JSON report of the vulnerabilities and anomalies which have
        been previously logged with the log* methods.
        """
        report_dict = {
            "classifications": self._flaw_types,
            "vulnerabilities": self._vulns,
            "anomalies": self._anomalies,
            "infos": self._infos
        }
        with open(output_path, "w") as f:
            json.dump(report_dict, f, indent=2)

    # Vulnerabilities
    def add_vulnerability_type(self, name, description="", solution="", references=None):
        """Add informations on a type of vulnerability"""
        if name not in self._flaw_types:
            self._flaw_types[name] = {
                "desc": description,
                "sol": solution,
                "ref": references
            }
        if name not in self._vulns:
            self._vulns[name] = []

    def add_vulnerability(self, category=None, level=0, request=None, parameter="", info=""):
        """
        Store the informations about a found vulnerability.
        """

        vuln_dict = {
            "method": request.method,
            "path": request.file_path,
            "info": info,
            "level": level,
            "parameter": parameter,
            "http_request": request.http_repr(left_margin=""),
            "curl_command": request.curl_repr,
        }
        if category not in self._vulns:
            self._vulns[category] = []
        self._vulns[category].append(vuln_dict)

    # Anomalies
    def add_anomaly_type(self, name, description="", solution="", references=None):
        """Register a type of anomaly"""
        if name not in self._flaw_types:
            self._flaw_types[name] = {
                "desc": description,
                "sol": solution,
                "ref": references
            }
        if name not in self._anomalies:
            self._anomalies[name] = []

    def add_anomaly(self, category=None, level=0, request=None, parameter="", info=""):
        """Store the informations about an anomaly met during the attack."""
        anom_dict = {
            "method": request.method,
            "path": request.file_path,
            "info": info,
            "level": level,
            "parameter": parameter,
            "http_request": request.http_repr(left_margin=""),
            "curl_command": request.curl_repr
        }
        if category not in self._anomalies:
            self._anomalies[category] = []
        self._anomalies[category].append(anom_dict)
