#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2008-2023 Nicolas Surribas
# Copyright (C) 2020-2024 Cyberwatch
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

from httpx import Response

from wapitiCore.net.response import detail_response
from wapitiCore.report.reportgenerator import ReportGenerator

NB_COLUMNS = 80

# TODO: should use more the python format mini-language
# http://docs.python.org/2/library/string.html#format-specification-mini-language


def center(row: str) -> str:
    if len(row) >= NB_COLUMNS:
        return row
    return row.rjust(len(row) + int((NB_COLUMNS - len(row)) / 2.0))


def title(row: str) -> str:
    return f"{row}\n{'-' * len(row.strip())}\n"


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
        self._additionals = {}

    def generate_report(self, output_path):
        """
        Create a TXT file encoded as UTF-8 with a report of the vulnerabilities which have been logged with
        the methods add_vulnerability and add_anomaly.
        """
        with codecs.open(output_path, mode="w", encoding="UTF-8") as txt_report_file:
            try:
                txt_report_file.write(separator)
                txt_report_file.write(center(f"{self._infos['version']} - wapiti-scanner.github.io\n"))
                txt_report_file.write(center(f"Report for {self._infos['target']}\n"))
                txt_report_file.write(center(f"Date of the scan : {self._infos['date']}\n"))
                txt_report_file.write(center(f"Crawled pages : {self._infos['crawled_pages_nbr']}\n"))
                if "scope" in self._infos:
                    txt_report_file.write(center(f"Scope of the scan : {self._infos['scope']}\n"))
                txt_report_file.write(separator)
                txt_report_file.write("\n")

                self._write_auth_info(txt_report_file)

                txt_report_file.write(title("Summary of vulnerabilities :"))
                for category, vulnerabilities in self._vulns.items():
                    txt_report_file.write(f"{category} : {len(vulnerabilities):>3}\n".rjust(NB_COLUMNS))
                txt_report_file.write(separator)

                for category, vulnerabilities in self._vulns.items():
                    if vulnerabilities:
                        txt_report_file.write("\n")
                        txt_report_file.write(title(category))
                        for vuln in vulnerabilities:
                            txt_report_file.write(vuln["info"])
                            txt_report_file.write("\n")
                            txt_report_file.write(f"WSTG code: {vuln['wstg']}")
                            txt_report_file.write("\n")
                            # f.write("Involved parameter : {0}\n".format(vuln["parameter"]))
                            txt_report_file.write("Evil request:\n")
                            txt_report_file.write(vuln["request"].http_repr())
                            txt_report_file.write("\n")
                            txt_report_file.write(f"cURL command PoC : \"{vuln['request'].curl_repr}\"")
                            txt_report_file.write("\n\n")
                            txt_report_file.write(center("*   *   *\n\n"))
                        txt_report_file.write(separator)

                txt_report_file.write("\n")

                txt_report_file.write(title("Summary of anomalies :"))
                for category, vulnerabilities in self._anomalies.items():
                    txt_report_file.write(f"{category} : {len(vulnerabilities):>3}\n".rjust(NB_COLUMNS))
                txt_report_file.write(separator)

                for category, anomalies in self._anomalies.items():
                    if anomalies:
                        txt_report_file.write("\n")
                        txt_report_file.write(title(category))
                        for anom in anomalies:
                            txt_report_file.write(anom["info"])
                            txt_report_file.write("\n")
                            txt_report_file.write(f"WSTG code: {anom['wstg']}")
                            txt_report_file.write("\n")
                            txt_report_file.write("Evil request:\n")
                            txt_report_file.write(anom["request"].http_repr())
                            txt_report_file.write("\n\n")
                            txt_report_file.write(center("*   *   *\n\n"))
                        txt_report_file.write(separator)

                txt_report_file.write(title("Summary of additionals :"))
                for category, additionnals in self._additionals.items():
                    txt_report_file.write(f"{category} : {len(additionnals):>3}\n".rjust(NB_COLUMNS))
                txt_report_file.write(separator)

                for category, additionnals in self._additionals.items():
                    if additionnals:
                        txt_report_file.write("\n")
                        txt_report_file.write(title(category))
                        for additional in additionnals:
                            txt_report_file.write(additional["info"])
                            txt_report_file.write("\n")
                            txt_report_file.write(f"WSTG: {additional['wstg']}")
                            txt_report_file.write("\n\n")
                            txt_report_file.write(center("*   *   *\n\n"))
                        txt_report_file.write(separator)

            finally:
                txt_report_file.close()

    # Vulnerabilities
    def add_vulnerability_type(self, name, description="", solution="", references=None, wstg=None):
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
                "ref": references,
                "wstg": wstg
            }
        if name not in self._vulns:
            self._vulns[name] = []

    def add_vulnerability(
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
        """
        Store the information about the vulnerability to be printed later.
        The method printToFile(fileName) can be used to save in a file the
        vulnerabilities notified through the current method.
        """

        vuln_dict = {
            "level": level,
            "request": request,
            "parameter": parameter,
            "info": info,
            "module": module,
            "wstg": wstg
        }
        if self._infos["detailed_report_level"]:
            vuln_dict["detail"] = {
                "response": detail_response(response)
            }
        if category not in self._vulns:
            self._vulns[category] = []
        self._vulns[category].append(vuln_dict)

    # Anomalies
    def add_anomaly_type(self, name, description="", solution="", references=None, wstg=None):
        if name not in self._flaw_types:
            self._flaw_types[name] = {
                "desc": description,
                "sol": solution,
                "ref": references,
                "wstg": wstg
            }
        if name not in self._anomalies:
            self._anomalies[name] = []

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
            "module": module,
            "wstg": wstg
        }
        if self._infos["detailed_report_level"]:
            anom_dict["detail"] = {
                "response": detail_response(response)
            }
        if category not in self._anomalies:
            self._anomalies[category] = []
        self._anomalies[category].append(anom_dict)

    # Additionals
    def add_additional_type(self, name, description="", solution="", references=None, wstg=None):
        """
        This method adds an addtional type, it can be invoked to include in the
        report the type.
        The types are not stored previously, they are added when the method
        add_addtional(category,level,url,parameter,info) is invoked
        and if there is no additional of a type, this type will not be presented
        in the report
        """
        if name not in self._flaw_types:
            self._flaw_types[name] = {
                "desc": description,
                "sol": solution,
                "ref": references,
                "wstg": wstg
            }
        if name not in self._additionals:
            self._additionals[name] = []

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
        """
        Store the information about the addtional to be printed later.
        The method printToFile(fileName) can be used to save in a file the
        additionals notified through the current method.
        """

        addition_dict = {
            "request": request,
            "info": info,
            "level": level,
            "parameter": parameter,
            "module": module,
            "wstg": wstg
        }
        if self._infos["detailed_report_level"]:
            addition_dict["detail"] = {
                "response": detail_response(response)
            }
        if category not in self._additionals:
            self._additionals[category] = []
        self._additionals[category].append(addition_dict)

    def _write_auth_info(self, txt_report_file: codecs.StreamReaderWriter):
        """
        Write the authentication section explaining what method, fields, url were used and also if it has been
        successful
        """
        if self._infos.get("auth") is None:
            return
        auth_dict = self._infos["auth"]
        txt_report_file.write(title("Authentication :"))
        txt_report_file.write(f"Url: {auth_dict['url']}\n")
        txt_report_file.write(f"Logged in: {auth_dict['logged_in']}\n")

        auth_form_dict = auth_dict.get("form")
        if auth_form_dict is None or len(auth_form_dict) == 0:
            return
        txt_report_file.write(f"Login field: {auth_form_dict['login_field']}\n")
        txt_report_file.write(f"Password field: {auth_form_dict['password_field']}\n")
        txt_report_file.write("\n")
        txt_report_file.write(separator)
