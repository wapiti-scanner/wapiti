#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (http://wapiti.sourceforge.io)
# Copyright (C) 2008-2020 Nicolas Surribas
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

from wapitiCore.attack.attack import Attack, PayloadType
from wapitiCore.language.vulnerability import Vulnerability, Anomaly, _


class mod_exec(Attack):
    """
    This class implements a command execution attack
    """

    PAYLOADS_FILE = "execPayloads.txt"

    name = "exec"

    @staticmethod
    def _find_pattern_in_response(data, warned: bool):
        vuln_info = ""
        executed = 0
        if "eval()'d code</b> on line <b>" in data and not warned:
            vuln_info = _("Warning eval()")
            warned = True
        if "PATH=" in data and "PWD=" in data:
            vuln_info = _("Command execution")
            executed = True
        if "COMPUTERNAME=" in data and "Program" in data:
            vuln_info = _("Command execution")
            executed = True
        if "w4p1t1_eval" in data or "1d97830e30da7214d3e121859cfa695f" in data:
            vuln_info = _("PHP evaluation")
            executed = True
        if "Cannot execute a blank command in" in data and not warned:
            vuln_info = _("Warning exec")
            warned = True
        if "sh: command substitution:" in data and not warned:
            vuln_info = _("Warning exec")
            warned = True
        if "Fatal error</b>:  preg_replace" in data and not warned:
            vuln_info = _("preg_replace injection")
            warned = True
        if "Warning: usort()" in data and not warned:
            vuln_info = _("Warning usort()")
            warned = True
        if "Warning: preg_replace():" in data and not warned:
            vuln_info = _("preg_replace injection")
            warned = True
        if "Warning: assert():" in data and not warned:
            vuln_info = _("Warning assert")
            warned = True
        if "Failure evaluating code:" in data and not warned:
            vuln_info = _("Evaluation warning")
            warned = True
        return vuln_info, executed, warned

    def attack(self):
        mutator = self.get_mutator()

        http_resources = self.persister.get_links(attack_module=self.name) if self.do_get else []
        forms = self.persister.get_forms(attack_module=self.name) if self.do_post else []

        false_positive_timeouts = set()

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

                    if PayloadType.time in flags and original_request.path_id in false_positive_timeouts:
                        # If the original request is known to gives timeout and payload is time-based, just skip
                        # and move to next payload
                        continue

                    if self.verbose == 2:
                        print("[¨] {0}".format(mutated_request))

                    try:
                        response = self.crawler.send(mutated_request)
                    except ReadTimeout:
                        if PayloadType.time in flags:
                            if self.does_timeout(original_request):
                                false_positive_timeouts.add(original_request.path_id)
                                continue

                            vuln_info = _("Blind command execution")
                            if parameter == "QUERY_STRING":
                                vuln_message = Vulnerability.MSG_QS_INJECT.format(vuln_info, page)
                            else:
                                vuln_message = _("{0} via injection in the parameter {1}").format(vuln_info, parameter)

                            self.add_vuln(
                                request_id=original_request.path_id,
                                category=Vulnerability.EXEC,
                                level=Vulnerability.HIGH_LEVEL,
                                request=mutated_request,
                                info=vuln_message,
                                parameter=parameter
                            )

                            self.log_red("---")
                            self.log_red(
                                Vulnerability.MSG_QS_INJECT if parameter == "QUERY_STRING"
                                else Vulnerability.MSG_PARAM_INJECT,
                                vuln_info,
                                page,
                                parameter
                            )
                            self.log_red(Vulnerability.MSG_EVIL_REQUEST)
                            self.log_red(mutated_request.http_repr())
                            self.log_red("---")
                            vulnerable_parameter = True
                            continue

                        elif timeouted:
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
                        # No timeout raised
                        vuln_info, executed, warned = self._find_pattern_in_response(response.content, warned)
                        if vuln_info:
                            # An error message implies that a vulnerability may exists

                            if parameter == "QUERY_STRING":
                                vuln_message = Vulnerability.MSG_QS_INJECT.format(vuln_info, page)
                                log_message = Vulnerability.MSG_QS_INJECT
                            else:
                                vuln_message = _("{0} via injection in the parameter {1}").format(vuln_info, parameter)
                                log_message = Vulnerability.MSG_PARAM_INJECT

                            self.add_vuln(
                                request_id=original_request.path_id,
                                category=Vulnerability.EXEC,
                                level=Vulnerability.HIGH_LEVEL,
                                request=mutated_request,
                                info=vuln_message,
                                parameter=parameter
                            )

                            self.log_red("---")
                            self.log_red(
                                log_message,
                                vuln_info,
                                page,
                                parameter
                            )
                            self.log_red(Vulnerability.MSG_EVIL_REQUEST)
                            self.log_red(mutated_request.http_repr())
                            self.log_red("---")

                            if executed:
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
