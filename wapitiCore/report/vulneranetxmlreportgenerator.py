#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (http://wapiti.sourceforge.io)
# Copyright (C) 2008-2020 Nicolas Surribas
#
# Original authors :
# David del Pozo
# Alberto Pastor
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
import datetime

from wapitiCore.report.reportgenerator import ReportGenerator


def is_peer_tuple(p):
    """Is p a (str,int) tuple? I.E. an (ip_address,port)"""
    if type(p) == tuple and len(p) == 2:
        return type(p[0]) == str and type(p[1]) == int
    else:
        return False


class VulneraNetXMLReportGenerator(ReportGenerator):
    """
    This class generates a report with the method printToFile(fileName) which contains
    the information of all the vulnerabilities notified to this object through the
    method add_vulnerability(category,level,url,parameter,info).
    The format of the file is XML and it has the following structure:
    <report type="security">
        <generatedBy id="Wapiti 3.0.3"/>
            <bugTypeList>
                <bugType name="SQL Injection">
                    <bugList/>

    <report>
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
        self._timestamp = datetime.datetime.now()
        self._xml_doc = Document()
        self._vulnerability_type_list = None

    def set_report_info(self, target, scope, date, version):
        super().set_report_info(target, scope, date, version)
        report = self._xml_doc.createElement("Report")

        report.setAttribute("generatedBy", version)
        report.setAttribute("generationDate", self._timestamp.isoformat())
        self._vulnerability_type_list = self._xml_doc.createElement("VulnerabilityTypeList")
        report.appendChild(self._vulnerability_type_list)

        self._xml_doc.appendChild(report)

    def _add_to_vulnerability_type_list(self, vulnerability_type):
        self._vulnerability_type_list.appendChild(vulnerability_type)

    def add_vulnerability_type(self, name, description="", solution="", references=None):
        """
        This method adds a vulnerability type, it can be invoked to include in the
        report the type.
        The types are not stored previously, they are added when the method
        add_vulnerability(category,level,url,parameter,info) is invoked
        and if there is no vulnerability of a type, this type will not be presented
        in the report
        """
        vulnerability_type = self._xml_doc.createElement("VulnerabilityType")
        vulnerability_type.appendChild(self._xml_doc.createElement("VulnerabilityList"))

        vuln_title_node = self._xml_doc.createElement("Title")
        vuln_title_node.appendChild(self._xml_doc.createTextNode(name))
        vulnerability_type.appendChild(vuln_title_node)

        self._add_to_vulnerability_type_list(vulnerability_type)
        if description != "":
            description_node = self._xml_doc.createElement("Description")
            description_node.appendChild(self._xml_doc.createCDATASection(description))
            vulnerability_type.appendChild(description_node)
        if solution != "":
            solution_node = self._xml_doc.createElement("Solution")
            solution_node.appendChild(self._xml_doc.createCDATASection(solution))
            vulnerability_type.appendChild(solution_node)
        if references != "":
            references_node = self._xml_doc.createElement("References")
            for ref in references:
                reference_node = self._xml_doc.createElement("Reference")
                name_node = self._xml_doc.createElement("name")
                url_node = self._xml_doc.createElement("url")
                name_node.appendChild(self._xml_doc.createTextNode(ref))
                url_node.appendChild(self._xml_doc.createTextNode(references[ref]))
                reference_node.appendChild(name_node)
                reference_node.appendChild(url_node)
                references_node.appendChild(reference_node)
            vulnerability_type.appendChild(references_node)
        return vulnerability_type

    def _add_to_vulnerability_list(self, category, vulnerability):
        vulnerability_type = None
        for node in self._vulnerability_type_list.childNodes:
            title_node = node.getElementsByTagName("Title")
            if (title_node.length >= 1 and
                    title_node[0].childNodes.length == 1 and
                    title_node[0].childNodes[0].wholeText == category):
                vulnerability_type = node
                break
        if vulnerability_type is None:
            vulnerability_type = self.add_vulnerability_type(category)
        vulnerability_type.childNodes[0].appendChild(vulnerability)

    def add_vulnerability(self, category=None, level=0, request=None, parameter="", info=""):
        """
        Store the information about the vulnerability to be printed later.
        The method printToFile(fileName) can be used to save in a file the
        vulnerabilities notified through the current method.
        """

        peer = None

        vulnerability = self._xml_doc.createElement("Vulnerability")

        if level == 1:
            st_level = "Low"
        elif level == 2:
            st_level = "Moderate"
        else:
            st_level = "Important"

        level_node = self._xml_doc.createElement("Severity")
        level_node.appendChild(self._xml_doc.createTextNode(st_level))
        vulnerability.appendChild(level_node)

        ts_node = self._xml_doc.createElement("DetectionDate")
        # tsNode.appendChild(self.__xmlDoc.createTextNode(ts.isoformat()))
        vulnerability.appendChild(ts_node)

        ##
        url_detail_node = self._xml_doc.createElement("URLDetail")
        vulnerability.appendChild(url_detail_node)

        url_node = self._xml_doc.createElement("URL")
        url_node.appendChild(self._xml_doc.createTextNode(request.url))
        url_detail_node.appendChild(url_node)

        if peer is not None:
            peer_node = self._xml_doc.createElement("Peer")
            if is_peer_tuple(peer):
                addr_node = self._xml_doc.createElement("Addr")
                addr_node.appendChild(self._xml_doc.createTextNode(peer[0]))
                peer_node.appendChild(addr_node)

                port_node = self._xml_doc.createElement("Port")
                port_node.appendChild(self._xml_doc.createTextNode(str(peer[1])))
                peer_node.appendChild(port_node)
            else:
                addr_node = self._xml_doc.createElement("Addr")
                addr_node.appendChild(self._xml_doc.createTextNode(str(peer)))
                peer_node.appendChild(addr_node)
            url_detail_node.appendChild(peer_node)

        parameter_node = self._xml_doc.createElement("Parameter")
        parameter_node.appendChild(self._xml_doc.createTextNode(parameter))
        url_detail_node.appendChild(parameter_node)

        ##

        info_node = self._xml_doc.createElement("Info")
        info = info.replace("\n", "<br />")
        info_node.appendChild(self._xml_doc.createTextNode(info))
        url_detail_node.appendChild(info_node)

        self._add_to_vulnerability_list(category, vulnerability)

    def generate_report(self, output_path):
        """
        Create a xml file with a report of the vulnerabilities which have been logged with
        the method add_vulnerability(category,level,url,parameter,info)
        """
        with open(output_path, "w") as fd:
            self._xml_doc.writexml(fd, addindent="   ", newl="\n")
