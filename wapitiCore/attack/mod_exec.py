#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2008-2023 Nicolas Surribas
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
from os.path import join as path_join
from typing import Optional, Iterator

from httpx import ReadTimeout, RequestError

from wapitiCore.main.log import log_red, log_verbose, log_orange
from wapitiCore.attack.attack import Attack
from wapitiCore.language.vulnerability import Messages
from wapitiCore.definitions.exec import NAME, WSTG_CODE
from wapitiCore.model import PayloadInfo
from wapitiCore.net.response import Response
from wapitiCore.definitions.resource_consumption import WSTG_CODE as RESOURCE_CONSUMPTION_WSTG_CODE
from wapitiCore.definitions.internal_error import WSTG_CODE as INTERNAL_ERROR_WSTG_CODE
from wapitiCore.net import Request
from wapitiCore.parsers.ini_payload_parser import IniPayloadReader, replace_tags


class ModuleExec(Attack):
    """
    Detect scripts vulnerable to command and/or code execution.
    """
    name = "exec"

    def __init__(self, crawler, persister, attack_options, stop_event, crawler_configuration):
        super().__init__(crawler, persister, attack_options, stop_event, crawler_configuration)
        self.false_positive_timeouts = set()
        self.mutator = self.get_mutator()

    def get_payloads(self) -> Iterator[PayloadInfo]:
        """Load the payloads from the specified file"""
        parser = IniPayloadReader(path_join(self.DATA_DIR, "execPayloads.ini"))
        parser.add_key_handler("payload", replace_tags)
        parser.add_key_handler("rules", lambda x: x.splitlines() if x else [])

        yield from parser

    @staticmethod
    def _find_warning_in_response(data) -> str:
        vuln_info = ""
        if "eval()'d code</b> on line <b>" in data:
            vuln_info = "Warning eval()"
        if "Cannot execute a blank command in" in data:
            vuln_info = "Warning exec"
        if "sh: command substitution:" in data:
            vuln_info = "Warning exec"
        if "Fatal error</b>:  preg_replace" in data:
            vuln_info = "preg_replace injection"
        if "Warning: usort()" in data:
            vuln_info = "Warning usort()"
        if "Warning: preg_replace():" in data:
            vuln_info = "preg_replace injection"
        if "Warning: assert():" in data:
            vuln_info = "Warning assert"
        if "Failure evaluating code:" in data:
            vuln_info = "Evaluation warning"
        return vuln_info

    async def attack(self, request: Request, response: Optional[Response] = None):
        warned = False
        timeouted = False
        page = request.path
        saw_internal_error = False
        current_parameter = None
        vulnerable_parameter = False

        for mutated_request, parameter, payload_info in self.mutator.mutate(request, self.get_payloads):

            if current_parameter != parameter:
                # Forget what we know about current parameter
                current_parameter = parameter
                vulnerable_parameter = False
            elif vulnerable_parameter:
                # If parameter is vulnerable, just skip till next parameter
                continue

            if payload_info.type == "time" and request.path_id in self.false_positive_timeouts:
                # If the original request is known to gives timeout and payload is time-based, just skip
                # and move to next payload
                continue

            log_verbose(f"[¨] {mutated_request}")

            try:
                response: Response = await self.crawler.async_send(mutated_request)
            except ReadTimeout:
                # Is the webpage expected to timeout?
                if payload_info.type == "time":
                    # Check for false-positive by asking the original request
                    if await self.does_timeout(request):
                        self.network_errors += 1
                        self.false_positive_timeouts.add(request.path_id)
                        continue

                    vuln_info = "Blind command execution"
                    if parameter.is_qs_injection:
                        vuln_message = Messages.MSG_QS_INJECT.format(vuln_info, page)
                    else:
                        vuln_message = f"{vuln_info} via injection in the parameter {parameter.display_name}"

                    await self.add_vuln_critical(
                        request_id=request.path_id,
                        category=NAME,
                        request=mutated_request,
                        info=vuln_message,
                        parameter=parameter.display_name,
                        wstg=WSTG_CODE
                    )

                    log_red("---")
                    log_red(
                        Messages.MSG_QS_INJECT if parameter.is_qs_injection else Messages.MSG_PARAM_INJECT,
                        vuln_info,
                        page,
                        parameter.display_name
                    )
                    log_red(Messages.MSG_EVIL_REQUEST)
                    log_red(mutated_request.http_repr())
                    log_red("---")
                    vulnerable_parameter = True
                    continue

                # We didn't expect the webpage to timeout, this is an error
                self.network_errors += 1
                if timeouted:
                    continue

                # Log the request as a new timeout case
                log_orange("---")
                log_orange(Messages.MSG_TIMEOUT, page)
                log_orange(Messages.MSG_EVIL_REQUEST)
                log_orange(mutated_request.http_repr())
                log_orange("---")

                if parameter.is_qs_injection:
                    anom_msg = Messages.MSG_QS_TIMEOUT
                else:
                    anom_msg = Messages.MSG_PARAM_TIMEOUT.format(parameter.display_name)

                await self.add_anom_medium(
                    request_id=request.path_id,
                    category=Messages.RES_CONSUMPTION,
                    request=mutated_request,
                    info=anom_msg,
                    parameter=parameter.display_name,
                    wstg=RESOURCE_CONSUMPTION_WSTG_CODE
                )
                timeouted = True
            except RequestError:
                self.network_errors += 1
            else:
                if payload_info.type == "time":
                    continue

                vuln_info = None

                # No timeout raised, check for patterns in response
                if all(rule in response.content for rule in payload_info.rules):
                    vuln_info = payload_info.description
                    # We reached maximum exploitation for this parameter, don't send more payloads
                    vulnerable_parameter = True
                elif not warned:
                    vuln_info = self._find_warning_in_response(response.content)
                    warned = True

                if vuln_info:
                    # An error message implies that a vulnerability may exist

                    if parameter.is_qs_injection:
                        vuln_message = Messages.MSG_QS_INJECT.format(vuln_info, page)
                        log_message = Messages.MSG_QS_INJECT
                    else:
                        vuln_message = f"{vuln_info} via injection in the parameter {parameter.display_name}"
                        log_message = Messages.MSG_PARAM_INJECT

                    await self.add_vuln_critical(
                        request_id=request.path_id,
                        category=NAME,
                        request=mutated_request,
                        info=vuln_message,
                        parameter=parameter.display_name,
                        wstg=WSTG_CODE,
                        response=response
                    )

                    log_red("---")
                    log_red(
                        log_message,
                        vuln_info,
                        page,
                        parameter.display_name
                    )
                    log_red(Messages.MSG_EVIL_REQUEST)
                    log_red(mutated_request.http_repr())
                    log_red("---")
                elif response.is_server_error and not saw_internal_error:
                    saw_internal_error = True
                    if parameter.is_qs_injection:
                        anom_msg = Messages.MSG_QS_500
                    else:
                        anom_msg = Messages.MSG_PARAM_500.format(parameter.display_name)

                    await self.add_anom_high(
                        request_id=request.path_id,
                        category=Messages.ERROR_500,
                        request=mutated_request,
                        info=anom_msg,
                        parameter=parameter.display_name,
                        wstg=INTERNAL_ERROR_WSTG_CODE
                    )

                    log_orange("---")
                    log_orange(Messages.MSG_500, page)
                    log_orange(Messages.MSG_EVIL_REQUEST)
                    log_orange(mutated_request.http_repr())
                    log_orange("---")
