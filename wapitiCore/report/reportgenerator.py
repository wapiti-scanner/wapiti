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

from wapitiCore.net.response import detail_response


class ReportGenerator:
    def __init__(self):
        self._infos = {}
        self._date = None
        self._flaw_types = {}
        self._vulns = {}
        self._anomalies = {}
        self._additionals = {}

    # pylint: disable=too-many-positional-arguments
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
        """
        This method adds a vulnerability type, it can be invoked to include in the
        report the type.
        The types are not stored previously, they are added when the method
        add_vulnerability(category, level, url, parameter, info) is invoked
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

    # pylint: disable=too-many-positional-arguments
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
        if self._infos.get("detailed_report_level"):
            vuln_dict["detail"] = {
                "response": detail_response(response)
            }
        if category not in self._vulns:
            self._vulns[category] = []
        self._vulns[category].append(vuln_dict)

    # Anomalies
    def add_anomaly_type(self, name, description="", solution="", references=None, wstg=None):
        """
        This method adds an anomaly type, it can be invoked to include in the
        report the type.
        The types are not stored previously, they are added when the method
        add_anomaly(category, level, url, parameter, info) is invoked,
        and if there is no anomaly of a type, this type will not be presented
        in the report
        """
        if name not in self._flaw_types:
            self._flaw_types[name] = {
                "desc": description,
                "sol": solution,
                "ref": references,
                "wstg": wstg
            }
        if name not in self._anomalies:
            self._anomalies[name] = []

    # pylint: disable=too-many-positional-arguments
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
        Store the information about the anomaly to be printed later.
        The method printToFile(fileName) can be used to save in a file the
        anomalies notified through the current method.
        """
        anom_dict = {
            "request": request,
            "info": info,
            "level": level,
            "parameter": parameter,
            "module": module,
            "wstg": wstg
        }
        if self._infos.get("detailed_report_level"):
            anom_dict["detail"] = {
                "response": detail_response(response)
            }
        if category not in self._anomalies:
            self._anomalies[category] = []
        self._anomalies[category].append(anom_dict)

    # Additionals
    def add_additional_type(self, name, description="", solution="", references=None, wstg=None):
        """
        This method adds an "additional" type, it can be invoked to include in the
        report the type.
        The types are not stored previously, they are added when the method
        add_addtional(category, level, url, parameter, info) is invoked,
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

    # pylint: disable=too-many-positional-arguments
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
        Store the information about the additional to be printed later.
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
        if self._infos.get("detailed_report_level"):
            addition_dict["detail"] = {
                "response": detail_response(response)
            }
        if category not in self._additionals:
            self._additionals[category] = []
        self._additionals[category].append(addition_dict)
