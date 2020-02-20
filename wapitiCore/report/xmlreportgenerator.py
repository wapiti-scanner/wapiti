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
from xml.dom.minidom import Document

from wapitiCore.report.reportgenerator import ReportGenerator


class XMLReportGenerator(ReportGenerator):
    """
    This class generates a report with the method printToFile(fileName) which contains
    the information of all the vulnerabilities notified to this object through the
    method add_vulnerability(vulnerabilityTypeName,level,url,parameter,info).
    The format of the file is XML and it has the following structure:
    <report type="security">
        <generatedBy id="Wapiti 3.0.3"/>
        <vulnerabilityTypeList>
            <vulnerabilityType name="SQL Injection">

        <vulnerabilityTypeList>
            <vulnerabilityType name="SQL Injection">
                <vulnerabilityList>
                    <vulnerability level="3">
                        <url>http://www.a.com</url>
                        <parameters>id=23</parameters>
                        <info>SQL Injection</info>
                    </vulnerability>
                </vulnerabilityList>
            </vulnerabilityType>
        </vulnerabilityTypeList>
    </report>
    """

    def __init__(self):
        super().__init__()
        self._xml_doc = Document()
        self._flaw_types = {}

        self._vulns = {}
        self._anomalies = {}

    # Vulnerabilities
    def add_vulnerability_type(self, name, description="", solution="", references=None):
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
            "method": request.method,
            "path": request.file_path,
            "info": info,
            "level": level,
            "parameter": parameter,
            "http_request": request.http_repr(left_margin=""),
            "curl_command": request.curl_repr,
        }
        if category not in self._anomalies:
            self._anomalies[category] = []
        self._anomalies[category].append(anom_dict)

    def generate_report(self, output_path):
        """
        Create a xml file with a report of the vulnerabilities which have been logged with
        the method add_vulnerability(vulnerabilityTypeName,level,url,parameter,info)
        """

        report = self._xml_doc.createElement("report")
        report.setAttribute("type", "security")
        self._xml_doc.appendChild(report)

        # Add report infos
        report_infos = self._xml_doc.createElement("report_infos")
        generator_name = self._xml_doc.createElement("info")
        generator_name.setAttribute("name", "generatorName")
        generator_name.appendChild(self._xml_doc.createTextNode("wapiti"))
        report_infos.appendChild(generator_name)

        generator_version = self._xml_doc.createElement("info")
        generator_version.setAttribute("name", "generatorVersion")
        generator_version.appendChild(self._xml_doc.createTextNode(self._infos["version"]))
        report_infos.appendChild(generator_version)

        scope = self._xml_doc.createElement("info")
        scope.setAttribute("name", "scope")
        scope.appendChild(self._xml_doc.createTextNode(self._infos["scope"]))
        report_infos.appendChild(scope)

        date_of_scan = self._xml_doc.createElement("info")
        date_of_scan.setAttribute("name", "dateOfScan")
        date_of_scan.appendChild(self._xml_doc.createTextNode(self._infos["date"]))
        report_infos.appendChild(date_of_scan)

        target = self._xml_doc.createElement("info")
        target.setAttribute("name", "target")
        target.appendChild(self._xml_doc.createTextNode(self._infos["target"]))
        report_infos.appendChild(target)

        report.appendChild(report_infos)

        vulnerabilities = self._xml_doc.createElement("vulnerabilities")
        anomalies = self._xml_doc.createElement("anomalies")

        # Loop on each flaw classification
        for flaw_type in self._flaw_types:
            container = None
            classification = ""
            flaw_dict = {}
            if flaw_type in self._vulns:
                container = vulnerabilities
                classification = "vulnerability"
                flaw_dict = self._vulns
            elif flaw_type in self._anomalies:
                container = anomalies
                classification = "anomaly"
                flaw_dict = self._anomalies

            # Child nodes with a description of the flaw type
            flaw_type_node = self._xml_doc.createElement(classification)
            flaw_type_node.setAttribute("name", flaw_type)
            flaw_type_desc = self._xml_doc.createElement("description")
            flaw_type_desc.appendChild(self._xml_doc.createCDATASection(self._flaw_types[flaw_type]["desc"]))
            flaw_type_node.appendChild(flaw_type_desc)
            flaw_type_solution = self._xml_doc.createElement("solution")
            flaw_type_solution.appendChild(self._xml_doc.createCDATASection(self._flaw_types[flaw_type]["sol"]))
            flaw_type_node.appendChild(flaw_type_solution)

            flaw_type_references = self._xml_doc.createElement("references")
            for ref in self._flaw_types[flaw_type]["ref"]:
                reference_node = self._xml_doc.createElement("reference")
                title_node = self._xml_doc.createElement("title")
                url_node = self._xml_doc.createElement("url")
                title_node.appendChild(self._xml_doc.createTextNode(ref))
                url = self._flaw_types[flaw_type]["ref"][ref]
                url_node.appendChild(self._xml_doc.createTextNode(url))
                reference_node.appendChild(title_node)
                reference_node.appendChild(url_node)
                flaw_type_references.appendChild(reference_node)
            flaw_type_node.appendChild(flaw_type_references)

            # And child nodes with each flaw of the current type
            entries_node = self._xml_doc.createElement("entries")
            for flaw in flaw_dict[flaw_type]:
                entry_node = self._xml_doc.createElement("entry")
                method_node = self._xml_doc.createElement("method")
                method_node.appendChild(self._xml_doc.createTextNode(flaw["method"]))
                entry_node.appendChild(method_node)
                path_node = self._xml_doc.createElement("path")
                path_node.appendChild(self._xml_doc.createTextNode(flaw["path"]))
                entry_node.appendChild(path_node)
                level_node = self._xml_doc.createElement("level")
                level_node.appendChild(self._xml_doc.createTextNode(str(flaw["level"])))
                entry_node.appendChild(level_node)
                parameter_node = self._xml_doc.createElement("parameter")
                parameter_node.appendChild(self._xml_doc.createTextNode(flaw["parameter"]))
                entry_node.appendChild(parameter_node)
                info_node = self._xml_doc.createElement("info")
                info_node.appendChild(self._xml_doc.createTextNode(flaw["info"]))
                entry_node.appendChild(info_node)
                http_request_node = self._xml_doc.createElement("http_request")
                http_request_node.appendChild(self._xml_doc.createCDATASection(flaw["http_request"]))
                entry_node.appendChild(http_request_node)
                curl_command_node = self._xml_doc.createElement("curl_command")
                curl_command_node.appendChild(self._xml_doc.createCDATASection(flaw["curl_command"]))
                entry_node.appendChild(curl_command_node)
                entries_node.appendChild(entry_node)
            flaw_type_node.appendChild(entries_node)
            container.appendChild(flaw_type_node)
        report.appendChild(vulnerabilities)
        report.appendChild(anomalies)

        with open(output_path, "w") as fd:
            self._xml_doc.writexml(fd, addindent="   ", newl="\n")
