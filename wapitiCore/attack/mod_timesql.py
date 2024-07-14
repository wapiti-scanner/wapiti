#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2008-2023 Nicolas Surribas
# Copyright (C) 2021-2024 Cyberwatch
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
from math import ceil
from os.path import join as path_join
from typing import Optional, Iterator

from httpx import ReadTimeout, RequestError

from wapitiCore.main.log import log_verbose, log_red, log_orange, logging
from wapitiCore.attack.attack import Attack, Parameter
from wapitiCore.language.vulnerability import Messages
from wapitiCore.definitions.sql import SqlInjectionFinding
from wapitiCore.definitions.internal_error import InternalErrorFinding
from wapitiCore.model import PayloadInfo
from wapitiCore.net import Request, Response
from wapitiCore.parsers.ini_payload_parser import IniPayloadReader, replace_tags


class ModuleTimesql(Attack):
    """
    Detect SQL injection vulnerabilities using blind time-based technique.
    """
    time_to_sleep = 6
    name = "timesql"
    PRIORITY = 6

    MSG_VULN = "Blind SQL vulnerability"

    def __init__(self, crawler, persister, attack_options, stop_event, crawler_configuration):
        Attack.__init__(self, crawler, persister, attack_options, stop_event, crawler_configuration)
        self.mutator = self.get_mutator()
        self.time_to_sleep = ceil(attack_options.get("timeout", self.time_to_sleep)) + 1

    def get_payloads(self, _: Optional[Request] = None, __: Optional[Parameter] = None) -> Iterator[PayloadInfo]:
        """Load the payloads from the specified file"""
        parser = IniPayloadReader(path_join(self.DATA_DIR, "blindSQLPayloads.ini"))
        parser.add_key_handler("payload", replace_tags)
        parser.add_key_handler("payload", lambda x: x.replace("[TIME]", str(self.time_to_sleep)))

        yield from parser

    async def attack(self, request: Request, response: Optional[Response] = None):
        page = request.path
        saw_internal_error = False
        current_parameter = None
        vulnerable_parameter = False

        for mutated_request, parameter, _payload in self.mutator.mutate(request, self.get_payloads):

            if current_parameter != parameter:
                # Forget what we know about current parameter
                current_parameter = parameter
                vulnerable_parameter = False
            elif vulnerable_parameter:
                # If parameter is vulnerable, just skip till next parameter
                continue

            log_verbose(f"[¨] {mutated_request}")

            try:
                response = await self.crawler.async_send(mutated_request, timeout=self.time_to_sleep)
            except ReadTimeout:
                # The request with time based payload did timeout, what about a regular request?
                if await self.does_timeout(request, timeout=self.time_to_sleep):
                    self.network_errors += 1
                    logging.error("[!] Too much lag from website, can't reliably test time-based blind SQL")
                    break

                if parameter.is_qs_injection:
                    vuln_message = Messages.MSG_QS_INJECT.format(self.MSG_VULN, page)
                    log_message = Messages.MSG_QS_INJECT
                else:
                    vuln_message = f"{self.MSG_VULN} via injection in the parameter {parameter.display_name}"
                    log_message = Messages.MSG_PARAM_INJECT

                await self.add_critical(
                    request_id=request.path_id,
                    finding_class=SqlInjectionFinding,
                    request=mutated_request,
                    info=vuln_message,
                    parameter=parameter.display_name,
                )

                log_red("---")
                log_red(
                    log_message,
                    self.MSG_VULN,
                    page,
                    parameter.display_name
                )
                log_red(Messages.MSG_EVIL_REQUEST)
                log_red(mutated_request.http_repr())
                log_red("---")

                # We reached maximum exploitation for this parameter, don't send more payloads
                vulnerable_parameter = True
                continue
            except RequestError:
                self.network_errors += 1
                continue
            else:
                if response.is_server_error and not saw_internal_error:
                    saw_internal_error = True
                    if parameter.is_qs_injection:
                        anom_msg = Messages.MSG_QS_500
                    else:
                        anom_msg = Messages.MSG_PARAM_500.format(parameter.display_name)

                    await self.add_high(
                        request_id=request.path_id,
                        finding_class=InternalErrorFinding,
                        request=mutated_request,
                        info=anom_msg,
                        parameter=parameter.display_name,
                        response=response
                    )

                    log_orange("---")
                    log_orange(Messages.MSG_500, page)
                    log_orange(Messages.MSG_EVIL_REQUEST)
                    log_orange(mutated_request.http_repr())
                    log_orange("---")
