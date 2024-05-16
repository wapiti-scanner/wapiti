#!/usr/bin/env python3

# HTML Report Generator Module for Wapiti Project
# Wapiti Project (https://wapiti-scanner.github.io)
#
# Copyright (C) 2017-2023 Nicolas SURRIBAS
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

import os
from shutil import copytree, rmtree, copy
from urllib.parse import urlparse
import time
from pkg_resources import resource_filename

from mako.template import Template

from wapitiCore.report.jsonreportgenerator import JSONReportGenerator
from wapitiCore.language.vulnerability import CRITICAL_LEVEL, HIGH_LEVEL, MEDIUM_LEVEL, LOW_LEVEL, INFO_LEVEL


def level_to_emoji(level: int) -> str:
    if level == CRITICAL_LEVEL:
        return "🔥"
    if level == HIGH_LEVEL:
        return "🔴"
    if level == MEDIUM_LEVEL:
        return "🟠"
    if level == LOW_LEVEL:
        return "🟡"
    if level == INFO_LEVEL:
        return "🕵️"
    return ""


class HTMLReportGenerator(JSONReportGenerator):
    """
    This class generates a Wapiti scan report in HTML format.
    """

    def __init__(self):
        super().__init__()
        self._final__path = None

    REPORT_DIR = "report_template"

    def generate_report(self, output_path):
        """
        Copy the report structure in the specified 'output_path' directory.
        If this directory already exists, overwrite the template files and add the HTML report.
        (This way we keep previous generated HTML files).
        """
        if os.path.isdir(output_path):
            for subdir in ("css", "js"):
                try:
                    rmtree(os.path.join(output_path, subdir))
                except FileNotFoundError:
                    pass

                copytree(
                    resource_filename("wapitiCore", os.path.join(self.REPORT_DIR, subdir)),
                    os.path.join(output_path, subdir)
                )

            copy(resource_filename("wapitiCore", os.path.join(self.REPORT_DIR, "logo_clear.png")), output_path)
        else:
            copytree(resource_filename("wapitiCore", self.REPORT_DIR), output_path)

        mytemplate = Template(
            filename=resource_filename("wapitiCore", os.path.join(self.REPORT_DIR, "report.html")),
            input_encoding="utf-8",
            output_encoding="utf-8"
        )

        report_target_name = urlparse(self._infos['target']).netloc.replace(':', '_')
        report_time = time.strftime('%m%d%Y_%H%M', self._date)

        filename = f"{report_target_name}_{report_time}.html"

        self._final__path = os.path.join(output_path, filename)

        with open(self._final__path, "w", encoding='utf-8') as html_report_file:
            html_report_file.write(
                mytemplate.render_unicode(
                    wapiti_version=self._infos["version"],
                    target=self._infos["target"],
                    scan_date=self._infos["date"],
                    scan_scope=self._infos["scope"],
                    auth_dict=self._infos["auth"],
                    auth_form_dict=self._infos["auth"]["form"] if self._infos.get("auth") is not None else None,
                    crawled_pages_nbr=self._infos["crawled_pages_nbr"],
                    vulnerabilities=self._vulns,
                    anomalies=self._anomalies,
                    additionals=self._additionals,
                    flaws=self._flaw_types,
                    level_to_emoji=level_to_emoji,
                    detailed_report_level=self._infos["detailed_report_level"]
                )
            )

    @property
    def final_path(self):
        return self._final__path
