#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2019-2023 Nicolas Surribas
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
from binascii import unhexlify
from asyncio import sleep
from typing import Optional, Iterator
from urllib.parse import quote
from os.path import join as path_join

from httpx import ReadTimeout, RequestError

from wapitiCore.main.log import logging, log_red, log_orange, log_verbose
from wapitiCore.attack.attack import Attack, XXEUploadMutator, Mutator, Parameter
from wapitiCore.language.vulnerability import Messages
from wapitiCore.definitions.xxe import XxeFinding
from wapitiCore.definitions.resource_consumption import ResourceConsumptionFinding
from wapitiCore.definitions.internal_error import InternalErrorFinding
from wapitiCore.model import PayloadInfo
from wapitiCore.net import Request, Response
from wapitiCore.parsers.ini_payload_parser import IniPayloadReader, replace_tags


def search_patterns(content: str, patterns: list) -> str:
    for pattern in patterns:
        if pattern in content:
            return pattern
    return ""


class ModuleXxe(Attack):
    """Detect scripts vulnerable to XML external entity injection (also known as XXE)."""

    name = "xxe"
    do_get = True
    do_post = True

    MSG_VULN = "XXE vulnerability"

    def __init__(self, crawler, persister, attack_options, stop_event, crawler_configuration):
        Attack.__init__(self, crawler, persister, attack_options, stop_event, crawler_configuration)
        self.vulnerables = set()
        self.attacked_urls = set()
        self.payload_to_rules = {}
        self.mutator = self.get_mutator()

    def get_payloads(self, _: Optional[Request] = None, __: Optional[Parameter] = None) -> Iterator[PayloadInfo]:
        """Load the payloads from the specified file"""
        parser = IniPayloadReader(path_join(self.DATA_DIR, "xxePayloads.ini"))
        parser.add_key_handler("payload", replace_tags)
        parser.add_key_handler("payload", lambda x: x.replace("[EXTERNAL_ENDPOINT]", self.external_endpoint))
        parser.add_key_handler("payload", lambda x: x.replace("[SESSION_ID]", self._session_id))
        parser.add_key_handler("rules", lambda x: x.splitlines())

        yield from parser

    def get_mutator(self):
        methods = ""
        if self.do_get:
            methods += "G"
        if self.do_post:
            # No file uploads, we won't attack filenames but file contents
            methods += "P"

        return Mutator(
            methods=methods,
            qs_inject=self.must_attack_query_string,
            skip=self.options.get("skipped_parameters")
        )

    async def false_positive(self, request: Request, pattern: str) -> bool:
        try:
            response = await self.crawler.async_send(request)
        except RequestError:
            self.network_errors += 1
            return False
        else:
            return pattern in response.content

    def flag_to_patterns(self, flags):
        try:
            return self.payload_to_rules[flags.section]
        except AttributeError:
            return []

    async def attack(self, request: Request, response: Optional[Response] = None):
        timeouted = False
        page = request.path
        saw_internal_error = False
        current_parameter = None
        vulnerable_parameter = False

        if request.url not in self.attacked_urls:
            await self.attack_body(request)
            self.attacked_urls.add(request.url)

        if request.path_id in self.vulnerables:
            return

        if request.is_multipart:
            await self.attack_upload(request)
            if request.path_id in self.vulnerables:
                return

        for mutated_request, parameter, payload_info in self.mutator.mutate(request, self.get_payloads):
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
                self.network_errors += 1
                if timeouted:
                    continue

                log_orange("---")
                log_orange(Messages.MSG_TIMEOUT, page)
                log_orange(Messages.MSG_EVIL_REQUEST)
                log_orange(mutated_request.http_repr())
                log_orange("---")

                if parameter.is_qs_injection:
                    anom_msg = Messages.MSG_QS_TIMEOUT
                else:
                    anom_msg = Messages.MSG_PARAM_TIMEOUT.format(parameter.display_name)

                await self.add_medium(
                    request_id=request.path_id,
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
                pattern = search_patterns(response.content, payload_info.rules)
                if pattern and not await self.false_positive(request, pattern):
                    # An error message implies that a vulnerability may exist
                    if parameter.is_qs_injection:
                        vuln_message = Messages.MSG_QS_INJECT.format(self.MSG_VULN, page)
                    else:
                        vuln_message = f"{self.MSG_VULN} via injection in the parameter {parameter.display_name}"

                    await self.add_high(
                        request_id=request.path_id,
                        finding_class=XxeFinding,
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
                    log_red(mutated_request.http_repr())
                    log_red("---")

                    # We reached maximum exploitation for this parameter, don't send more payloads
                    vulnerable_parameter = True
                    continue

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

    async def attack_body(self, original_request):
        for payload_info in self.get_payloads():
            payload = payload_info.payload
            payload = payload.replace("[PATH_ID]", str(original_request.path_id))
            payload = payload.replace("[PARAM_AS_HEX]", "72617720626f6479")  # raw body
            mutated_request = Request(original_request.url, method="POST", enctype="text/xml", post_params=payload)

            log_verbose(f"[¨] {mutated_request}")

            try:
                response = await self.crawler.async_send(mutated_request)
            except RequestError:
                self.network_errors += 1
                continue
            else:
                pattern = search_patterns(response.content, payload_info.rules)
                if pattern and not await self.false_positive(original_request, pattern):
                    await self.add_high(
                        request_id=original_request.path_id,
                        finding_class=XxeFinding,
                        request=mutated_request,
                        info="XXE vulnerability leading to file disclosure",
                        parameter="raw body",
                        response=response
                    )

                    log_red("---")
                    log_red(
                        "{0} in {1} leading to file disclosure",
                        self.MSG_VULN,
                        original_request.url
                    )
                    log_red(Messages.MSG_EVIL_REQUEST)
                    log_red(mutated_request.http_repr())
                    log_red("---")
                    self.vulnerables.add(original_request.path_id)
                    break

    async def attack_upload(self, original_request):
        mutator = XXEUploadMutator()
        current_parameter = None
        vulnerable_parameter = False

        for mutated_request, parameter, payload_info in mutator.mutate(original_request, self.get_payloads):
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
            except RequestError:
                self.network_errors += 1
            else:
                pattern = search_patterns(response.content, payload_info.rules)
                if pattern and not await self.false_positive(original_request, pattern):
                    await self.add_high(
                        request_id=original_request.path_id,
                        finding_class=XxeFinding,
                        request=mutated_request,
                        info="XXE vulnerability leading to file disclosure",
                        parameter=parameter.display_name,
                        response=response
                    )

                    log_red("---")
                    log_red(
                        Messages.MSG_PARAM_INJECT,
                        self.MSG_VULN,
                        original_request.url,
                        parameter.display_name
                    )
                    log_red(Messages.MSG_EVIL_REQUEST)
                    log_red(mutated_request.http_repr())
                    log_red("---")
                    vulnerable_parameter = True
                    self.vulnerables.add(original_request.path_id)

    async def finish(self):
        endpoint_url = f"{self.internal_endpoint}get_xxe.php?session_id={self._session_id}"
        logging.info(f"[*] Asking endpoint URL {endpoint_url} for results, please wait...")
        await sleep(2)
        # When attacks are done we ask the endpoint for received requests
        try:
            response = await self.crawler.async_send(Request(endpoint_url))
        except RequestError:
            self.network_errors += 1
            logging.error(f"[!] Unable to request endpoint URL '{self.internal_endpoint}'")
            return

        data = response.json
        if not isinstance(data, dict):
            return

        for request_id in data:
            original_request = await self.persister.get_path_by_id(request_id)
            if original_request is None:
                continue

            page = original_request.path
            for hex_param in data[request_id]:
                parameter_name = unhexlify(hex_param).decode("utf-8")

                for infos in data[request_id][hex_param]:
                    request_url = infos["url"]
                    # Date in ISO format
                    request_date = infos["date"]
                    request_ip = infos["ip"]
                    request_size = infos["size"]
                    payload_name = infos["payload"]

                    if parameter_name == "QUERY_STRING":
                        vuln_message = Messages.MSG_QS_INJECT.format(self.MSG_VULN, page)
                    elif parameter_name == "raw body":
                        vuln_message = f"Out-Of-Band {self.MSG_VULN} by sending raw XML in request body"
                    else:
                        vuln_message = f"Out-Of-Band {self.MSG_VULN} via injection in the parameter {parameter_name}"

                    if not request_size:
                        # Overwrite the message as the full exploit chain failed
                        vuln_message = (
                            "The target reached the DTD file on the endpoint but the exploitation didn't succeed."
                        )
                    else:
                        # Exploitation succeed, we have some data
                        more_infos = (
                            f"The target sent {request_size} bytes of data to the endpoint at {request_date} "
                            f"with IP {request_ip}.\n"
                            f"Received data can be seen at {request_url}."
                        )
                        vuln_message += "\n" + more_infos

                    for payload_info in self.get_payloads():
                        payload = payload_info.payload
                        if f"{payload_name}.dtd" in payload:
                            payload = payload.replace("[PATH_ID]", str(original_request.path_id))
                            payload = payload.replace("[PARAM_AS_HEX]", "72617720626f6479")
                            used_payload = payload_info
                            used_payload.payload = payload
                            break
                    else:
                        # The request we got did not match any existing payload
                        continue

                    if parameter_name == "raw body":
                        mutated_request = Request(
                            original_request.path,
                            method="POST",
                            enctype="text/xml",
                            post_params=payload
                        )
                    elif parameter_name == "QUERY_STRING":
                        mutated_request = Request(
                            f"{original_request.path}?{quote(payload)}",
                            method="GET"
                        )
                    elif parameter_name in original_request.get_keys or parameter_name in original_request.post_keys:
                        mutator = Mutator(
                            methods="G" if original_request.method == "GET" else "P",
                            qs_inject=self.must_attack_query_string,
                            parameters=[parameter_name],
                            skip=self.options.get("skipped_parameters")
                        )

                        mutated_request, __, __ = next(mutator.mutate(original_request, [used_payload]))
                    else:
                        mutator = XXEUploadMutator(
                            parameters=[parameter_name],
                            skip=self.options.get("skipped_parameters")
                        )
                        mutated_request, __, __ = next(mutator.mutate(original_request, [used_payload]))

                    if request_size:
                        add_vuln_method = self.add_high
                        log_method = log_red
                    else:
                        add_vuln_method = self.add_medium
                        log_method = log_orange

                    await add_vuln_method(
                        request_id=original_request.path_id,
                        finding_class=XxeFinding,
                        request=mutated_request,
                        info=vuln_message,
                        parameter=parameter_name,
                    )

                    log_method("---")
                    log_method(vuln_message)
                    log_method(Messages.MSG_EVIL_REQUEST)
                    log_method(mutated_request.http_repr())
                    log_method("---")
