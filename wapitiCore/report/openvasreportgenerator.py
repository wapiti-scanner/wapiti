#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (http://wapiti.sourceforge.io)
# Copyright (C) 2013-2020 Nicolas Surribas
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
import uuid

from wapitiCore.report.reportgenerator import ReportGenerator


class OpenVASReportGenerator(ReportGenerator):
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

        self._vuln_count = 0
        self._anom_count = 0

    # Vulnerabilities
    def add_vulnerability_type(self, name, description="", solution="", references=None):
        if name not in self._flaw_types:
            self._flaw_types[name] = {
                'desc': description,
                'sol': solution,
                'ref': references}
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
            "hostname": request.hostname,
            "port": request.port,
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
        self._vuln_count += 1

    # Anomalies
    def add_anomaly_type(self, name, description="", solution="", references=None):
        if name not in self._flaw_types:
            self._flaw_types[name] = {
                'desc': description,
                'sol': solution,
                'ref': references
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
            "hostname": request.hostname,
            "port": request.port,
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
        self._anom_count += 1

    def generate_report(self, output_path):
        """
        Create a xml file with a report of the vulnerabilities which have been logged with
        the method add_vulnerability(vulnerabilityTypeName,level,url,parameter,info)
        """

        uuid_report = str(uuid.uuid1())
        report = self._xml_doc.createElement("report")
        report.setAttribute("extension", "xml")
        report.setAttribute("id", uuid_report)
        report.setAttribute("type", "scan")
        report.setAttribute("content_type", "text/html")
        report.setAttribute("format_id", "a994b278-1f62-11e1-96ac-406186ea4fc5")
        self._xml_doc.appendChild(report)

        # Add report infos
        report_infos = self._xml_doc.createElement("report")
        report_infos.setAttribute("id", uuid_report)

        scan_run_status = self._xml_doc.createElement("scan_run_status")
        scan_run_status.appendChild(self._xml_doc.createTextNode("Done"))
        report_infos.appendChild(scan_run_status)

        scan_start = self._xml_doc.createElement("scan_start")
        scan_start.appendChild(self._xml_doc.createTextNode(self._infos["date"]))
        report_infos.appendChild(scan_start)

        results = self._xml_doc.createElement("results")
        results.setAttribute("start", "1")
        results.setAttribute("max", str(self._vuln_count + self._anom_count))

        # Loop on each flaw classification
        for flawType in self._flaw_types:
            classification = ""
            flaw_dict = {}
            if flawType in self._vulns:
                classification = "vulnerability"
                flaw_dict = self._vulns
            elif flawType in self._anomalies:
                classification = "anomaly"
                flaw_dict = self._anomalies

            for flaw in flaw_dict[flawType]:
                result = self._xml_doc.createElement("result")
                result.setAttribute("id", str(uuid.uuid4()))

                subnet = self._xml_doc.createElement("subnet")
                subnet.appendChild(self._xml_doc.createTextNode(flaw["hostname"]))
                result.appendChild(subnet)

                host = self._xml_doc.createElement("host")
                host.appendChild(self._xml_doc.createTextNode(flaw["hostname"]))
                result.appendChild(host)

                port = self._xml_doc.createElement("port")
                port.appendChild(self._xml_doc.createTextNode(str(flaw["port"])))
                result.appendChild(port)

                nvt = self._xml_doc.createElement("nvt")
                nvt.setAttribute("oid", str(uuid.uuid4()))

                name = self._xml_doc.createElement("name")
                name.appendChild(self._xml_doc.createTextNode(flawType))
                nvt.appendChild(name)

                family = self._xml_doc.createElement("family")
                family.appendChild(self._xml_doc.createTextNode(classification))
                nvt.appendChild(family)

                cvss_base = self._xml_doc.createElement("cvss_base")
                cvss_base.appendChild(self._xml_doc.createTextNode("0.0"))
                nvt.appendChild(cvss_base)

                risk_factor = self._xml_doc.createElement("risk_factor")
                risk_factor.appendChild(self._xml_doc.createTextNode(str(flaw["level"])))
                nvt.appendChild(risk_factor)

                cve = self._xml_doc.createElement("cve")
                cve.appendChild(self._xml_doc.createTextNode(""))
                nvt.appendChild(cve)

                bid = self._xml_doc.createElement("bid")
                bid.appendChild(self._xml_doc.createTextNode(""))
                nvt.appendChild(bid)

                tags = self._xml_doc.createElement("tags")
                tags.appendChild(self._xml_doc.createTextNode(""))
                nvt.appendChild(tags)

                certs = self._xml_doc.createElement("certs")
                certs.appendChild(self._xml_doc.createTextNode(""))
                nvt.appendChild(certs)

                xref = self._xml_doc.createElement("xref")
                xref.appendChild(self._xml_doc.createTextNode("NOXREF"))
                nvt.appendChild(xref)

                result.appendChild(nvt)

                threat = self._xml_doc.createElement("threat")
                threat.appendChild(self._xml_doc.createTextNode(str(flaw["level"])))
                result.appendChild(threat)

                description = self._xml_doc.createElement("description")
                description.appendChild(self._xml_doc.createCDATASection(flaw["info"]))
                result.appendChild(description)

                original_threat = self._xml_doc.createElement("original_threat")
                original_threat.appendChild(self._xml_doc.createTextNode(str(flaw["level"])))
                result.appendChild(original_threat)

                results.appendChild(result)

        report_infos.appendChild(results)
        report.appendChild(report_infos)

        with open(output_path, "w") as fd:
            self._xml_doc.writexml(fd, addindent="   ", newl="\n")
