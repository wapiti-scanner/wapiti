#!/usr/bin/env python3

# HTML Report Generator Module for Wapiti Project
# Wapiti Project (http://wapiti.sourceforge.io)
#
# Copyright (C) 2017-2020 Nicolas SURRIBAS
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
import sys
from shutil import copytree, rmtree, copy
from urllib.parse import urlparse
import time

from mako.template import Template

from wapitiCore.report.jsonreportgenerator import JSONReportGenerator


class HTMLReportGenerator(JSONReportGenerator):
    """
    This class generates a Wapiti scan report in HTML format.
    """
    def __init__(self):
        super().__init__()
        self._final__path = None

    BASE_DIR = os.path.dirname(sys.modules["wapitiCore"].__file__)
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

                copytree(os.path.join(self.BASE_DIR, self.REPORT_DIR, subdir), os.path.join(output_path, subdir))
            copy(os.path.join(self.BASE_DIR, self.REPORT_DIR, "logo_clear.png"), output_path)
        else:
            copytree(os.path.join(self.BASE_DIR, self.REPORT_DIR), output_path)

        mytemplate = Template(
            filename=os.path.join(self.BASE_DIR, self.REPORT_DIR, "report.html"),
            input_encoding="utf-8",
            output_encoding="utf-8"
        )

        filename = "{}_{}.html".format(
            urlparse(self._infos["target"]).netloc.replace(":", "_"),
            time.strftime("%m%d%Y_%H%M", self._date)
        )
        self._final__path = os.path.join(output_path, filename)

        with open(self._final__path, "w") as fd:
            fd.write(
                mytemplate.render_unicode(
                    wapiti_version=self._infos["version"],
                    target=self._infos["target"],
                    scan_date=self._infos["date"],
                    scan_scope=self._infos["scope"],
                    vulnerabilities=self._vulns,
                    anomalies=self._anomalies,
                    flaws=self._flaw_types
                )
            )

    @property
    def final_path(self):
        return self._final__path
