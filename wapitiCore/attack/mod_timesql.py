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
from httpx import ReadTimeout, RequestError

from wapitiCore.main.log import log_verbose, log_red, log_orange, logging
from wapitiCore.attack.attack import Attack
from wapitiCore.language.vulnerability import Messages, _
from wapitiCore.definitions.timesql import NAME
from wapitiCore.net.web import Request


class ModuleTimesql(Attack):
    """
    Detect SQL injection vulnerabilities using blind time-based technique.
    """

    PAYLOADS_FILE = "blindSQLPayloads.txt"
    time_to_sleep = 6
    name = "timesql"
    PRIORITY = 6

    MSG_VULN = _("Blind SQL vulnerability")

    def __init__(self, crawler, persister, attack_options, stop_event):
        Attack.__init__(self, crawler, persister, attack_options, stop_event)
        self.mutator = self.get_mutator()

    def set_timeout(self, timeout):
        self.time_to_sleep = str(1 + int(timeout))

    async def attack(self, request: Request):
        page = request.path
        saw_internal_error = False
        current_parameter = None
        vulnerable_parameter = False

        for mutated_request, parameter, _payload, _flags in self.mutator.mutate(request):
            if current_parameter != parameter:
                # Forget what we know about current parameter
                current_parameter = parameter
                vulnerable_parameter = False
            elif vulnerable_parameter:
                # If parameter is vulnerable, just skip till next parameter
                continue

            log_verbose(f"[¨] {mutated_request}")

            try:
                response = await self.crawler.async_send(mutated_request)
            except ReadTimeout:
                # The request with time based payload did timeout, what about a regular request?
                if await self.does_timeout(request):
                    self.network_errors += 1
                    logging.error("[!] Too much lag from website, can't reliably test time-based blind SQL")
                    break

                if parameter == "QUERY_STRING":
                    vuln_message = Messages.MSG_QS_INJECT.format(self.MSG_VULN, page)
                    log_message = Messages.MSG_QS_INJECT
                else:
                    vuln_message = _("{0} via injection in the parameter {1}").format(self.MSG_VULN, parameter)
                    log_message = Messages.MSG_PARAM_INJECT

                await self.add_vuln_critical(
                    request_id=request.path_id,
                    category=NAME,
                    request=mutated_request,
                    info=vuln_message,
                    parameter=parameter
                )

                log_red("---")
                log_red(
                    log_message,
                    self.MSG_VULN,
                    page,
                    parameter
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
                if response.status == 500 and not saw_internal_error:
                    saw_internal_error = True
                    if parameter == "QUERY_STRING":
                        anom_msg = Messages.MSG_QS_500
                    else:
                        anom_msg = Messages.MSG_PARAM_500.format(parameter)

                    await self.add_anom_high(
                        request_id=request.path_id,
                        category=Messages.ERROR_500,
                        request=mutated_request,
                        info=anom_msg,
                        parameter=parameter
                    )

                    log_orange("---")
                    log_orange(Messages.MSG_500, page)
                    log_orange(Messages.MSG_EVIL_REQUEST)
                    log_orange(mutated_request.http_repr())
                    log_orange("---")
