#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti.sourceforge.io)
# Copyright (C) 2008-2021 Nicolas Surribas
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
from requests.exceptions import ReadTimeout

from wapitiCore.attack.attack import Attack, PayloadType
from wapitiCore.language.vulnerability import Messages, HIGH_LEVEL, MEDIUM_LEVEL, CRITICAL_LEVEL, _
from wapitiCore.definitions.exec import NAME
from wapitiCore.net.web import Request


class mod_exec(Attack):
    """
    Detect scripts vulnerable to command and/or code execution.
    """

    PAYLOADS_FILE = "execPayloads.txt"

    name = "exec"

    def __init__(self, crawler, persister, logger, attack_options):
        super().__init__(crawler, persister, logger, attack_options)
        self.false_positive_timeouts = set()
        self.mutator = self.get_mutator()

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

    def attack(self, request: Request):
        warned = False
        timeouted = False
        page = request.path
        saw_internal_error = False
        current_parameter = None
        vulnerable_parameter = False

        for mutated_request, parameter, payload, flags in self.mutator.mutate(request):
            if current_parameter != parameter:
                # Forget what we know about current parameter
                current_parameter = parameter
                vulnerable_parameter = False
            elif vulnerable_parameter:
                # If parameter is vulnerable, just skip till next parameter
                continue

            if flags.type == PayloadType.time and request.path_id in self.false_positive_timeouts:
                # If the original request is known to gives timeout and payload is time-based, just skip
                # and move to next payload
                continue

            if self.verbose == 2:
                print("[¨] {0}".format(mutated_request))

            try:
                response = self.crawler.send(mutated_request)
            except ReadTimeout:
                if flags.type == PayloadType.time:
                    if self.does_timeout(request):
                        self.false_positive_timeouts.add(request.path_id)
                        continue

                    vuln_info = _("Blind command execution")
                    if parameter == "QUERY_STRING":
                        vuln_message = Messages.MSG_QS_INJECT.format(vuln_info, page)
                    else:
                        vuln_message = _("{0} via injection in the parameter {1}").format(vuln_info, parameter)

                    self.add_vuln(
                        request_id=request.path_id,
                        category=NAME,
                        level=CRITICAL_LEVEL,
                        request=mutated_request,
                        info=vuln_message,
                        parameter=parameter
                    )

                    self.log_red("---")
                    self.log_red(
                        Messages.MSG_QS_INJECT if parameter == "QUERY_STRING"
                        else Messages.MSG_PARAM_INJECT,
                        vuln_info,
                        page,
                        parameter
                    )
                    self.log_red(Messages.MSG_EVIL_REQUEST)
                    self.log_red(mutated_request.http_repr())
                    self.log_red("---")
                    vulnerable_parameter = True
                    continue

                elif timeouted:
                    continue

                self.log_orange("---")
                self.log_orange(Messages.MSG_TIMEOUT, page)
                self.log_orange(Messages.MSG_EVIL_REQUEST)
                self.log_orange(mutated_request.http_repr())
                self.log_orange("---")

                if parameter == "QUERY_STRING":
                    anom_msg = Messages.MSG_QS_TIMEOUT
                else:
                    anom_msg = Messages.MSG_PARAM_TIMEOUT.format(parameter)

                self.add_anom(
                    request_id=request.path_id,
                    category=Messages.RES_CONSUMPTION,
                    level=MEDIUM_LEVEL,
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
                        vuln_message = Messages.MSG_QS_INJECT.format(vuln_info, page)
                        log_message = Messages.MSG_QS_INJECT
                    else:
                        vuln_message = _("{0} via injection in the parameter {1}").format(vuln_info, parameter)
                        log_message = Messages.MSG_PARAM_INJECT

                    self.add_vuln(
                        request_id=request.path_id,
                        category=NAME,
                        level=CRITICAL_LEVEL,
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
                    self.log_red(Messages.MSG_EVIL_REQUEST)
                    self.log_red(mutated_request.http_repr())
                    self.log_red("---")

                    if executed:
                        # We reached maximum exploitation for this parameter, don't send more payloads
                        vulnerable_parameter = True
                        continue

                elif response.status == 500 and not saw_internal_error:
                    saw_internal_error = True
                    if parameter == "QUERY_STRING":
                        anom_msg = Messages.MSG_QS_500
                    else:
                        anom_msg = Messages.MSG_PARAM_500.format(parameter)

                    self.add_anom(
                        request_id=request.path_id,
                        category=Messages.ERROR_500,
                        level=HIGH_LEVEL,
                        request=mutated_request,
                        info=anom_msg,
                        parameter=parameter
                    )

                    self.log_orange("---")
                    self.log_orange(Messages.MSG_500, page)
                    self.log_orange(Messages.MSG_EVIL_REQUEST)
                    self.log_orange(mutated_request.http_repr())
                    self.log_orange("---")
