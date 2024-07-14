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
from typing import Optional

from httpx import ReadTimeout, HTTPStatusError, RequestError

from wapitiCore.attack.attack import Attack
from wapitiCore.language.vulnerability import Messages
from wapitiCore.definitions.crlf import CrlfFinding
from wapitiCore.definitions.resource_consumption import ResourceConsumptionFinding
from wapitiCore.model import PayloadInfo, str_to_payloadinfo
from wapitiCore.net import Request, Response
from wapitiCore.main.log import logging, log_verbose, log_orange, log_red


class ModuleCrlf(Attack):
    """Detect Carriage Return Line Feed (CRLF) injection vulnerabilities."""
    # Won't work with PHP >= 4.4.2

    name = "crlf"
    MSG_VULN = "CRLF Injection"
    do_get = True
    do_post = True
    payloads = [PayloadInfo(payload="http://www.google.fr\r\nwapiti: 3.2.0 version")]

    def __init__(self, crawler, persister, attack_options, stop_event, crawler_configuration):
        super().__init__(crawler, persister, attack_options, stop_event, crawler_configuration)
        self.mutator = self.get_mutator()

    async def attack(self, request: Request, response: Optional[Response] = None):
        page = request.path

        for mutated_request, parameter, _payload in self.mutator.mutate(
                request,
                str_to_payloadinfo(["http://www.google.fr\r\nwapiti: 3.2.0 version"]),
        ):
            log_verbose(f"[¨] {mutated_request.url}")

            try:
                response = await self.crawler.async_send(mutated_request)
            except ReadTimeout:
                self.network_errors += 1
                await self.add_medium(
                    request_id=request.path_id,
                    finding_class=ResourceConsumptionFinding,
                    request=mutated_request,
                    parameter=parameter.display_name,
                    info="Timeout (" + parameter.display_name + ")",
                )

                log_orange("---")
                log_orange(Messages.MSG_TIMEOUT, page)
                log_orange(Messages.MSG_EVIL_REQUEST)
                log_orange(mutated_request.http_repr())
                log_orange("---")
            except HTTPStatusError:
                self.network_errors += 1
                logging.error("Error: The server did not understand this request")
            except RequestError:
                self.network_errors += 1
            else:
                if "wapiti" in response.headers:
                    await self.add_low(
                        request_id=request.path_id,
                        finding_class=CrlfFinding,
                        request=mutated_request,
                        parameter=parameter.display_name,
                        info=f"{self.MSG_VULN} via injection in the parameter {parameter.display_name}",
                        response=response,
                    )

                    if parameter.is_qs_injection:
                        injection_msg = Messages.MSG_QS_INJECT
                    else:
                        injection_msg = Messages.MSG_PARAM_INJECT

                    log_red("---")
                    log_red(
                        injection_msg,
                        self.MSG_VULN,
                        page,
                        parameter.display_name
                    )
                    log_red(Messages.MSG_EVIL_REQUEST)
                    log_red(mutated_request.http_repr())
                    log_red("---")
