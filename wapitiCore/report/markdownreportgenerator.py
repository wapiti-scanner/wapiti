#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2025 Nicolas Surribas
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

from wapitiCore.net.web import http_repr, curl_repr
from wapitiCore.report.reportgenerator import ReportGenerator


class MarkdownReportGenerator(ReportGenerator):
    """
    This class generates a Wapiti report in Markdown format.
    """

    def generate_report(self, output_path):
        """
        Create a Markdown file encoded as UTF-8 with a report of the vulnerabilities which have been logged with
        the methods add_vulnerability and add_anomaly.
        """
        with codecs.open(output_path, mode="w", encoding="UTF-8") as md_report_file:
            md_report_file.write(f"# {self._infos['version']} - wapiti-scanner.github.io\n\n")
            md_report_file.write(f"## Report for {self._infos['target']}\n")
            md_report_file.write(f"* Date of the scan : {self._infos['date']}\n")
            md_report_file.write(f"* Crawled pages : {self._infos['crawled_pages_nbr']}\n")
            if "scope" in self._infos:
                md_report_file.write(f"* Scope of the scan : {self._infos['scope']}\n")
            md_report_file.write("\n---\n\n")

            self._write_auth_info(md_report_file)

            md_report_file.write("## Summary of vulnerabilities\n\n")
            md_report_file.write("| Category | Count |\n")
            md_report_file.write("|---|---|\n")
            for category, vulnerabilities in self._vulns.items():
                md_report_file.write(f"| {category} | {len(vulnerabilities)} |\n")
            md_report_file.write("\n---\n\n")

            for category, vulnerabilities in self._vulns.items():
                if vulnerabilities:
                    md_report_file.write(f"### {category}\n")
                    for vuln in vulnerabilities:
                        md_report_file.write(f"**Info**: {vuln['info']}\n")
                        md_report_file.write(f"**WSTG code**: {vuln['wstg']}\n")
                        if vuln["parameter"] is not None:
                            md_report_file.write(f"**Involved parameter**: {vuln['parameter']}\n")
                        md_report_file.write("\n**Evil request**:\n\n")
                        md_report_file.write(f"```http\n{http_repr(vuln['request'])}\n```\n")
                        md_report_file.write("\n**cURL command PoC**:\n\n")
                        md_report_file.write(f"```bash\n{curl_repr(vuln['request'])}\n```\n\n")
                        md_report_file.write("---\n\n")
            md_report_file.write("\n")

            md_report_file.write("## Summary of anomalies\n\n")
            md_report_file.write("| Category | Count |\n")
            md_report_file.write("|---|---|\n")
            for category, vulnerabilities in self._anomalies.items():
                md_report_file.write(f"| {category} | {len(vulnerabilities)} |\n")
            md_report_file.write("\n---\n\n")

            for category, anomalies in self._anomalies.items():
                if anomalies:
                    md_report_file.write(f"### {category}\n")
                    for anom in anomalies:
                        md_report_file.write(f"**Info**: {anom['info']}\n")
                        md_report_file.write(f"**WSTG code**: {anom['wstg']}\n")
                        if anom["parameter"] is not None:
                            md_report_file.write(f"**Involved parameter**: {anom['parameter']}\n")
                        md_report_file.write("\n**Evil request**:\n\n")
                        md_report_file.write(f"```http\n{http_repr(anom['request'])}\n```\n")
                        md_report_file.write("\n**cURL command PoC**:\n\n")
                        md_report_file.write(f"```bash\n{curl_repr(anom['request'])}\n```\n\n")
                        md_report_file.write("---\n\n")
            md_report_file.write("\n")

            md_report_file.write("## Summary of additionals\n\n")
            md_report_file.write("| Category | Count |\n")
            md_report_file.write("|---|---|\n")
            for category, additionnals in self._additionals.items():
                md_report_file.write(f"| {category} | {len(additionnals)} |\n")
            md_report_file.write("\n---\n\n")

            for category, additionnals in self._additionals.items():
                if additionnals:
                    md_report_file.write(f"### {category}\n")
                    for additional in additionnals:
                        md_report_file.write(f"**Info**: {additional['info']}\n")
                        md_report_file.write(f"**WSTG**: {additional['wstg']}\n")
                        if additional["parameter"] is not None:
                            md_report_file.write(f"**Involved parameter**: {additional['parameter']}\n")
                        md_report_file.write("---\n\n")
            md_report_file.write("\n")

    def _write_auth_info(self, md_report_file: codecs.StreamReaderWriter):
        """
        Write the authentication section explaining what method, fields, url were used and also if it has been
        successful
        """
        if self._infos.get("auth") is None:
            return
        auth_dict = self._infos["auth"]
        md_report_file.write("## Authentication :\n")
        md_report_file.write(f"* Url: {auth_dict['url']}\n")
        md_report_file.write(f"* Logged in: {auth_dict['logged_in']}\n")

        auth_form_dict = auth_dict.get("form")
        if auth_form_dict is None or len(auth_form_dict) == 0:
            return
        md_report_file.write(f"* Login field: {auth_form_dict['login_field']}\n")
        md_report_file.write(f"* Password field: {auth_form_dict['password_field']}\n")
        md_report_file.write("\n---\n\n")
