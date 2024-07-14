#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2018-2023 Nicolas Surribas
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
from asyncio import sleep
from typing import Optional, Iterator
from binascii import hexlify, unhexlify

from httpx import RequestError

from wapitiCore.main.log import logging, log_red, log_verbose
from wapitiCore.attack.attack import Attack, Mutator, Parameter, ParameterSituation
from wapitiCore.language.vulnerability import Messages
from wapitiCore.definitions.ssrf import SsrfFinding
from wapitiCore.model import PayloadInfo, str_to_payloadinfo
from wapitiCore.net import Request, Response

SSRF_PAYLOAD = "{external_endpoint}ssrf/{random_id}/{path_id}/{hex_param}/"


class ModuleSsrf(Attack):
    """
    Detect Server-Side Request Forgery vulnerabilities.
    """

    name = "ssrf"
    MSG_VULN = "SSRF vulnerability"

    def __init__(self, crawler, persister, attack_options, stop_event, crawler_configuration):
        super().__init__(crawler, persister, attack_options, stop_event, crawler_configuration)
        self.mutator = self.get_mutator()

    def get_payloads(
            self,
            request: Optional[Request] = None,
            parameter: Optional[Parameter] = None,
    ) -> Iterator[PayloadInfo]:
        """Load the payloads from the specified file"""
        # The payload will contain the parameter name in hex-encoded format
        # If the injection is made directly in the query string (no parameter) then the payload would be
        # the hex value of "QUERY_STRING"
        if parameter.situation == ParameterSituation.QUERY_STRING and parameter.name == "":
            parameter_name = "QUERY_STRING"
        else:
            parameter_name = parameter.name

        payload = SSRF_PAYLOAD.format(
            external_endpoint=self.external_endpoint,
            random_id=self._session_id,
            path_id=request.path_id,
            hex_param=hexlify(parameter_name.encode("utf-8", errors="replace")).decode()
        )
        yield PayloadInfo(payload=payload)

    async def attack(self, request: Request, response: Optional[Response] = None):
        # Let's just send payloads, we don't care of the response as what we want to know is if the target
        # contacted the endpoint.
        for mutated_request, _parameter, _payload in self.mutator.mutate(request, self.get_payloads):
            log_verbose(f"[¨] {mutated_request}")

            try:
                await self.crawler.async_send(mutated_request)
            except RequestError:
                self.network_errors += 1
                continue

    async def finish(self):
        endpoint_url = f"{self.internal_endpoint}get_ssrf.php?session_id={self._session_id}"
        logging.info(f"[*] Asking endpoint URL {endpoint_url} for results, please wait...")
        await sleep(2)
        # When attacks are down we ask the endpoint for receive requests
        endpoint_request = Request(endpoint_url)
        try:
            response = await self.crawler.async_send(endpoint_request)
        except RequestError:
            self.network_errors += 1
            logging.error(f"[!] Unable to request endpoint URL '{self.internal_endpoint}'")
        else:
            data = response.json
            if isinstance(data, dict):
                for request_id in data:
                    original_request = await self.persister.get_path_by_id(request_id)
                    if original_request is None:
                        raise ValueError("Could not find the original request with that ID")

                    page = original_request.path
                    for hex_param in data[request_id]:
                        parameter = unhexlify(hex_param).decode("utf-8")

                        for infos in data[request_id][hex_param]:
                            request_url = infos["url"]
                            # Date in ISO format
                            request_date = infos["date"]
                            request_ip = infos["ip"]
                            request_method = infos["method"]
                            # request_size = infos["size"]

                            if parameter == "QUERY_STRING":
                                vuln_message = Messages.MSG_QS_INJECT.format(self.MSG_VULN, page)
                            else:
                                vuln_message = (
                                    f"{self.MSG_VULN} via injection in the parameter {parameter}.\n"
                                    f"The target performed an outgoing HTTP {request_method} request at {request_date} "
                                    f"with IP {request_ip}.\n"
                                    f"Full request can be seen at {request_url}"
                                )

                            mutator = Mutator(
                                methods="G" if original_request.method == "GET" else "PF",
                                qs_inject=self.must_attack_query_string,
                                parameters=[parameter],
                                skip=self.options.get("skipped_parameters")
                            )

                            mutated_request, __, __ = next(mutator.mutate(
                                original_request,
                                str_to_payloadinfo(["http://external.url/page"])
                            ))

                            await self.add_critical(
                                request_id=original_request.path_id,
                                finding_class=SsrfFinding,
                                request=mutated_request,
                                info=vuln_message,
                                parameter=parameter,
                                response=response
                            )

                            log_red("---")
                            log_red(
                                Messages.MSG_QS_INJECT if parameter == "QUERY_STRING"
                                else Messages.MSG_PARAM_INJECT,
                                self.MSG_VULN,
                                page,
                                parameter
                            )
                            log_red(Messages.MSG_EVIL_REQUEST)
                            log_red(mutated_request.http_repr())
                            log_red("---")
