#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (http://wapiti.sourceforge.io)
# Copyright (C) 2008-2020 Nicolas Surribas
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
import codecs

from wapitiCore.language.language import _
from wapitiCore.report.reportgenerator import ReportGenerator

NB_COLUMNS = 80


# TODO: should use more the python format mini-language
# http://docs.python.org/2/library/string.html#format-specification-mini-language


def center(s):
    if len(s) >= NB_COLUMNS:
        return s
    return s.rjust(len(s) + int((NB_COLUMNS - len(s)) / 2.0))


def title(s):
    return "{0}\n{1}\n".format(s, "-" * len(s.strip()))


separator = ("*" * NB_COLUMNS) + "\n"


class TXTReportGenerator(ReportGenerator):
    """
    This class generates a Wapiti report in TXT format.
    """

    def __init__(self):
        super().__init__()
        self._flaw_types = {}
        self._vulns = {}
        self._anomalies = {}

    def generate_report(self, output_path):
        """
        Create a TXT file encoded as UTF-8 with a report of the vulnerabilities which have been logged with
        the methods add_vulnerability and add_anomaly.
        """
        fd = codecs.open(output_path, mode="w", encoding="UTF-8")
        try:
            fd.write(separator)
            fd.write(center("{0} - wapiti.sourceforge.io\n".format(self._infos["version"])))
            fd.write(center(_("Report for {0}\n").format(self._infos["target"])))
            fd.write(center(_("Date of the scan : {0}\n").format(self._infos["date"])))
            if "scope" in self._infos:
                fd.write(center(_("Scope of the scan : {0}\n").format(self._infos["scope"])))
            fd.write(separator)
            fd.write("\n")

            fd.write(title(_("Summary of vulnerabilities :")))
            for name in self._vulns:
                fd.write(_("{0} : {1:>3}\n").format(name, len(self._vulns[name])).rjust(NB_COLUMNS))
            fd.write(separator)

            for name in self._vulns:
                if self._vulns[name]:
                    fd.write("\n")
                    fd.write(title(name))
                    for vuln in self._vulns[name]:
                        fd.write(vuln["info"])
                        fd.write("\n")
                        # f.write("Involved parameter : {0}\n".format(vuln["parameter"]))
                        fd.write(_("Evil request:\n"))
                        fd.write(vuln["request"].http_repr())
                        fd.write("\n")
                        fd.write(_("cURL command PoC : \"{0}\"").format(vuln["request"].curl_repr))
                        fd.write("\n\n")
                        fd.write(center("*   *   *\n\n"))
                    fd.write(separator)

            fd.write("\n")

            fd.write(title(_("Summary of anomalies :")))
            for name in self._anomalies:
                fd.write(_("{0} : {1:>3}\n").format(name, len(self._anomalies[name])).rjust(NB_COLUMNS))
            fd.write(separator)

            for name in self._anomalies:
                if self._anomalies[name]:
                    fd.write("\n")
                    fd.write(title(name))
                    for anom in self._anomalies[name]:
                        fd.write(anom["info"])
                        fd.write("\n")
                        fd.write(_("Evil request:\n"))
                        fd.write(anom["request"].http_repr())
                        fd.write("\n\n")
                        fd.write(center("*   *   *\n\n"))
                    fd.write(separator)

        finally:
            fd.close()

    # Vulnerabilities
    def add_vulnerability_type(self, name, description="", solution="", references=None):
        """
        This method adds a vulnerability type, it can be invoked to include in the
        report the type.
        The types are not stored previously, they are added when the method
        add_vulnerability(category,level,url,parameter,info) is invoked
        and if there is no vulnerability of a type, this type will not be presented
        in the report
        """

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
        Store the information about the vulnerability to be printed later.
        The method printToFile(fileName) can be used to save in a file the
        vulnerabilities notified through the current method.
        """

        if category not in self._vulns:
            self._vulns[category] = []
        self._vulns[category].append(
            {
                "level": level,
                "request": request,
                "parameter": parameter,
                "info": info
            }
        )

    # Anomalies
    def add_anomaly_type(self, name, description="", solution="", references=None):
        if name not in self._flaw_types:
            self._flaw_types[name] = {
                "desc": description,
                "sol": solution,
                "ref": references
            }
        if name not in self._anomalies:
            self._anomalies[name] = []

    def add_anomaly(self, category=None, level=0, request=None, parameter="", info=""):
        """
        Store the information about the vulnerability to be printed later.
        The method printToFile(fileName) can be used to save in a file the
        vulnerabilities notified through the current method.
        """

        anom_dict = {
            "request": request,
            "info": info,
            "level": level,
            "parameter": parameter,
        }
        if category not in self._anomalies:
            self._anomalies[category] = []
        self._anomalies[category].append(anom_dict)
