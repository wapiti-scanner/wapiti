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
from xml.dom.minidom import Document, Element

from wapitiCore.report.jsonreportgenerator import JSONReportGenerator


class XMLReportGenerator(JSONReportGenerator):
    """
    This class generates a report with the method printToFile(fileName) which contains
    the information of all the vulnerabilities notified to this object through the
    method add_vulnerability(vulnerabilityTypeName,level,url,parameter,info).
    The format of the file is XML and it has the following structure:
    <report type="security">
        <generatedBy id="Wapiti X.X.X"/>
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
        self._additionals = {}

    def generate_report(self, output_path):
        """
        Create a xml file with a report of the vulnerabilities which have been logged with
        the method add_vulnerability(vulnerabilityTypeName,level,url,parameter,info)
        """

        report = self._xml_doc.createElement("report")
        report.setAttribute("type", "security")
        self._xml_doc.appendChild(report)

        # Add report infos
        report_infos = self._create_info_section()
        report.appendChild(report_infos)

        vulnerabilities = self._xml_doc.createElement("vulnerabilities")
        anomalies = self._xml_doc.createElement("anomalies")
        additionals = self._xml_doc.createElement("additionals")

        # Loop on each flaw classification
        for flaw_type_name, flaw_type in self._flaw_types.items():
            container = None
            classification = ""
            flaw_dict = {}
            if flaw_type_name in self._vulns:
                container = vulnerabilities
                classification = "vulnerability"
                flaw_dict = self._vulns
            elif flaw_type_name in self._anomalies:
                container = anomalies
                classification = "anomaly"
                flaw_dict = self._anomalies
            elif flaw_type_name in self._additionals:
                container = additionals
                classification = "additional"
                flaw_dict = self._additionals

            # Child nodes with a description of the flaw type
            flaw_type_node = self._xml_doc.createElement(classification)
            flaw_type_node.setAttribute("name", flaw_type_name)
            flaw_type_desc = self._xml_doc.createElement("description")
            flaw_type_desc.appendChild(self._xml_doc.createCDATASection(flaw_type["desc"]))
            flaw_type_node.appendChild(flaw_type_desc)
            flaw_type_solution = self._xml_doc.createElement("solution")
            flaw_type_solution.appendChild(self._xml_doc.createCDATASection(flaw_type["sol"]))
            flaw_type_node.appendChild(flaw_type_solution)

            flaw_type_references = self._xml_doc.createElement("references")
            for ref in flaw_type["ref"]:
                reference_node = self._xml_doc.createElement("reference")
                title_node = self._xml_doc.createElement("title")
                url_node = self._xml_doc.createElement("url")
                title_node.appendChild(self._xml_doc.createTextNode(ref))
                url = flaw_type["ref"][ref]
                url_node.appendChild(self._xml_doc.createTextNode(url))
                wstg_node = self._xml_doc.createElement("wstg")
                for wstg_code in flaw_type["wstg"] or []:
                    wstg_code_node = self._xml_doc.createElement("code")
                    wstg_code_node.appendChild(self._xml_doc.createTextNode(wstg_code))
                    wstg_node.appendChild(wstg_code_node)
                reference_node.appendChild(title_node)
                reference_node.appendChild(url_node)
                reference_node.appendChild(wstg_node)
                flaw_type_references.appendChild(reference_node)
            flaw_type_node.appendChild(flaw_type_references)

            # And child nodes with each flaw of the current type
            entries_node = self._xml_doc.createElement("entries")
            for flaw in flaw_dict[flaw_type_name]:
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
                referer_node = self._xml_doc.createElement("referer")
                referer_node.appendChild(self._xml_doc.createTextNode(flaw["referer"]))
                entry_node.appendChild(referer_node)
                module_node = self._xml_doc.createElement("module")
                module_node.appendChild(self._xml_doc.createTextNode(flaw["module"]))
                entry_node.appendChild(module_node)
                http_request_node = self._xml_doc.createElement("http_request")
                http_request_node.appendChild(self._xml_doc.createCDATASection(flaw["http_request"]))
                entry_node.appendChild(http_request_node)
                curl_command_node = self._xml_doc.createElement("curl_command")
                curl_command_node.appendChild(self._xml_doc.createCDATASection(flaw["curl_command"]))
                entry_node.appendChild(curl_command_node)
                wstg_node = self._xml_doc.createElement("wstg")
                for wstg_code in flaw["wstg"] or []:
                    wstg_code_node = self._xml_doc.createElement("code")
                    wstg_code_node.appendChild(self._xml_doc.createTextNode(wstg_code))
                    wstg_node.appendChild(wstg_code_node)
                entry_node.appendChild(wstg_node)
                if self._infos["detailed_report_level"]:
                    entry_node.appendChild(self._create_detail_section(flaw))
                entries_node.appendChild(entry_node)
            flaw_type_node.appendChild(entries_node)
            container.appendChild(flaw_type_node)
        report.appendChild(vulnerabilities)
        report.appendChild(anomalies)
        report.appendChild(additionals)

        with open(output_path, "w", errors="ignore", encoding='utf-8') as xml_report_file:
            self._xml_doc.writexml(xml_report_file, addindent="   ", newl="\n")

    def _create_detail_section(self, flaw: dict) -> Element:
        """
        Create a section composed of the detail of the request & its response
        """
        detail_section = self._xml_doc.createElement("detail")
        detail_response_section = self._create_detail_response(flaw["detail"]["response"])
        if detail_response_section:
            detail_section.appendChild(detail_response_section)
        return detail_section

    def _create_detail_response(self, response: dict) -> Element:
        """
        Create a section focused on the exploit http request's response
        """
        if not response:
            return None
        response_section: Element = self._xml_doc.createElement("response")
        status_code_node = self._xml_doc.createElement("status_code")
        status_code_node.appendChild(self._xml_doc.createTextNode(str(response["status_code"])))
        response_section.appendChild(status_code_node)

        body_node = self._xml_doc.createElement("body")
        body_node.appendChild(self._xml_doc.createCDATASection(response["body"]))
        response_section.appendChild(body_node)

        headers_node = self._xml_doc.createElement("headers")
        for header in response.get("headers") or []:
            header_node = self._xml_doc.createElement("header")
            header_node.setAttribute("name", header[0])
            header_node.appendChild(self._xml_doc.createTextNode(header[1]))
            headers_node.appendChild(header_node)
        response_section.appendChild(headers_node)
        return response_section

    def _create_info_section(self) -> Element:
        """
        Write the authentication section explaining what method, fields, url were used and also if it has been
        successful
        """
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

        target = self._xml_doc.createElement("info")
        target.setAttribute("name", "crawledPages")
        target.appendChild(self._xml_doc.createTextNode(str(self._infos["crawled_pages_nbr"])))
        report_infos.appendChild(target)

        auth_node = self._xml_doc.createElement("info")
        auth_node.setAttribute("name", "auth")

        if self._infos.get("auth") is not None:
            auth_dict = self._infos["auth"]
            is_logged_in = "true" if auth_dict["logged_in"] is True else "false"

            auth_url_node = self._xml_doc.createElement("url")
            auth_url_node.appendChild(self._xml_doc.createTextNode(auth_dict["url"]))
            auth_node.appendChild(auth_url_node)
            auth_logged_in_node = self._xml_doc.createElement("logged_in")
            auth_logged_in_node.appendChild(self._xml_doc.createTextNode(is_logged_in))
            auth_node.appendChild(auth_logged_in_node)

            form_node = self._xml_doc.createElement("form")
            if auth_dict.get("form") is not None and len(auth_dict["form"]) > 0:
                auth_form_dict = auth_dict["form"]

                form_login_field_node = self._xml_doc.createElement("login_field")
                form_login_field_node.appendChild(self._xml_doc.createTextNode(auth_form_dict["login_field"]))
                form_node.appendChild(form_login_field_node)
                form_password_field_node = self._xml_doc.createElement("password_field")
                form_password_field_node.appendChild(self._xml_doc.createTextNode(auth_form_dict["password_field"]))
                form_node.appendChild(form_password_field_node)
                auth_node.appendChild(form_node)
            else:
                form_node.setAttributeNS("http://www.w3.org/2001/XMLSchema-instance", "xsi:nil", "true")
        else:
            auth_node.setAttributeNS("http://www.w3.org/2001/XMLSchema-instance", "xsi:nil", "true")
        report_infos.appendChild(auth_node)
        if self._infos["detailed_report_level"]:
            report_infos.appendChild(self._create_crawled_pages_section(self._infos["crawled_pages"]))
        return report_infos

    def _create_crawled_pages_section(self, crawled_pages: dict) -> Element:
        """
        Create a new section containing all the crawled pages with all the details of the requests and the responses
        """
        crawled_pages_node = self._xml_doc.createElement("crawled_pages")

        for crawled_page in crawled_pages:
            entry_section = self._xml_doc.createElement("entry")
            detail_response = self._create_detail_response(crawled_page["response"])
            if detail_response:
                entry_section.appendChild(detail_response)
            crawled_pages_node.appendChild(entry_section)
        return crawled_pages_node
