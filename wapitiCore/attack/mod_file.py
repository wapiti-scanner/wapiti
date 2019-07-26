#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (http://wapiti.sourceforge.net)
# Copyright (C) 2008-2019 Nicolas Surribas
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
from itertools import chain

from requests.exceptions import ReadTimeout, RequestException

from wapitiCore.attack.attack import Attack
from wapitiCore.language.vulnerability import Vulnerability, Anomaly, _


class mod_file(Attack):
    """This class implements a file handling attack"""

    PAYLOADS_FILE = "fileHandlingPayloads.txt"

    name = "file"

    # The following table contains tuples of (pattern, description, severity)
    # a severity of 1 is a file disclosure (inclusion, read etc) vulnerability
    # a severity of 0 is just the detection of an error returned by the server
    # Most important patterns must appear at the top of this table.
    warnings_desc = [
        # Vulnerabilities
        ("<title>Google</title>", _("Remote inclusion vulnerability"), 1),
        ("root:x:0:0", _("Linux local file disclosure vulnerability"), 1),
        ("root:*:0:0", _("BSD local file disclosure vulnerability"), 1),
        ("# Network services, Internet style", _("Unix local file disclosure vulnerability"), 1),
        ("[boot loader]", _("Windows local file disclosure vulnerability"), 1),
        ("for 16-bit app support", _("Windows local file disclosure vulnerability"), 1),
        ("s:12:\"pear.php.net\";", _("File disclosure vulnerability in include_path"), 1),
        ("PHP Extension and Application Reposit", _("File disclosure vulnerability in include_path"), 1),
        ("PEAR,&nbsp;the&nbsp;PHP&nbsp;Extensio", _("highlight_file() vulnerability in basedir"), 1),
        ("either use the CLI php executable", _("include() of file in include_path"), 1),
        # Warnings
        ("java.io.FileNotFoundException:", "Java include/open", 0),
        ("fread(): supplied argument is not", "fread()", 0),
        ("fpassthru(): supplied argument is not", "fpassthru()", 0),
        ("for inclusion (include_path=", "include()", 0),
        ("Failed opening required", "require()", 0),
        ("Warning: file(", "file()", 0),
        ("<b>Warning</b>:  file(", "file()", 0),
        ("Warning: readfile(", "readfile()", 0),
        ("<b>Warning:</b>  readfile(", "readfile()", 0),
        ("Warning: file_get_contents(", "file_get_contents()", 0),
        ("<b>Warning</b>:  file_get_contents(", "file_get_contents()", 0),
        ("Warning: show_source(", "show_source()", 0),
        ("<b>Warning:</b>  show_source(", "show_source()", 0),
        ("Warning: highlight_file(", "highlight_file()", 0),
        ("<b>Warning:</b>  highlight_file(", "highlight_file()", 0),
        ("System.IO.FileNotFoundException:", ".NET File.Open*", 0),
        ("error '800a0046'", "VBScript OpenTextFile", 0)
    ]

    def _find_pattern_in_response(self, data, warn):
        """This method searches patterns in the response from the server"""
        err_msg = ""
        inc = 0
        for pattern, description, level in self.warnings_desc:
            if pattern in data:
                if level == 1:
                    err_msg = description
                    inc = 1
                    break
                else:
                    if warn == 0:
                        err_msg = _("Possible {0} vulnerability").format(description)
                        warn = 1
                        break
        return err_msg, inc, warn

    def attack(self):
        mutator = self.get_mutator()

        http_resources = self.persister.get_links(attack_module=self.name) if self.do_get else []
        forms = self.persister.get_forms(attack_module=self.name) if self.do_post else []

        for original_request in chain(http_resources, forms):
            warned = False
            timeouted = False
            page = original_request.path
            saw_internal_error = False
            current_parameter = None
            vulnerable_parameter = False

            if self.verbose >= 1:
                print("[+] {}".format(original_request))

            for mutated_request, parameter, payload, flags in mutator.mutate(original_request):
                try:
                    if current_parameter != parameter:
                        # Forget what we know about current parameter
                        current_parameter = parameter
                        vulnerable_parameter = False
                    elif vulnerable_parameter:
                        # If parameter is vulnerable, just skip till next parameter
                        continue

                    if self.verbose == 2:
                        print("[¨] {0}".format(mutated_request))

                    try:
                        response = self.crawler.send(mutated_request)
                    except ReadTimeout:
                        if timeouted:
                            continue

                        self.log_orange("---")
                        self.log_orange(Anomaly.MSG_TIMEOUT, page)
                        self.log_orange(Anomaly.MSG_EVIL_REQUEST)
                        self.log_orange(mutated_request.http_repr())
                        self.log_orange("---")

                        if parameter == "QUERY_STRING":
                            anom_msg = Anomaly.MSG_QS_TIMEOUT
                        else:
                            anom_msg = Anomaly.MSG_PARAM_TIMEOUT.format(parameter)

                        self.add_anom(
                            request_id=original_request.path_id,
                            category=Anomaly.RES_CONSUMPTION,
                            level=Anomaly.MEDIUM_LEVEL,
                            request=mutated_request,
                            info=anom_msg,
                            parameter=parameter
                        )
                        timeouted = True
                    else:
                        vuln_info, inc, warn = self._find_pattern_in_response(response.content, warned)

                        if vuln_info:
                            # An error message implies that a vulnerability may exists
                            if parameter == "QUERY_STRING":
                                vuln_message = Vulnerability.MSG_QS_INJECT.format(vuln_info, page)
                            else:
                                vuln_message = _("{0} via injection in the parameter {1}").format(vuln_info, parameter)

                            self.add_vuln(
                                request_id=original_request.path_id,
                                category=Vulnerability.FILE_HANDLING,
                                level=Vulnerability.HIGH_LEVEL,
                                request=mutated_request,
                                info=vuln_message,
                                parameter=parameter
                            )

                            self.log_red("---")
                            self.log_red(
                                Vulnerability.MSG_QS_INJECT if parameter == "QUERY_STRING" else Vulnerability.MSG_PARAM_INJECT,
                                vuln_info,
                                page,
                                parameter
                            )
                            self.log_red(Vulnerability.MSG_EVIL_REQUEST)
                            self.log_red(mutated_request.http_repr())
                            self.log_red("---")

                            if inc:
                                # We reached maximum exploitation for this parameter, don't send more payloads
                                vulnerable_parameter = True
                                continue

                        elif response.status == 500 and not saw_internal_error:
                            saw_internal_error = True
                            if parameter == "QUERY_STRING":
                                anom_msg = Anomaly.MSG_QS_500
                            else:
                                anom_msg = Anomaly.MSG_PARAM_500.format(parameter)

                            self.add_anom(
                                request_id=original_request.path_id,
                                category=Anomaly.ERROR_500,
                                level=Anomaly.HIGH_LEVEL,
                                request=mutated_request,
                                info=anom_msg,
                                parameter=parameter
                            )

                            self.log_orange("---")
                            self.log_orange(Anomaly.MSG_500, page)
                            self.log_orange(Anomaly.MSG_EVIL_REQUEST)
                            self.log_orange(mutated_request.http_repr())
                            self.log_orange("---")
                except (KeyboardInterrupt, RequestException) as exception:
                    yield exception

            yield original_request
