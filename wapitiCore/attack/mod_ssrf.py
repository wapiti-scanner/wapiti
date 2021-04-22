#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti.sourceforge.io)
# Copyright (C) 2018-2021 Nicolas Surribas
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
from urllib.parse import quote
from binascii import hexlify, unhexlify

from httpx import RequestError

from wapitiCore.attack.attack import Attack, Mutator, PayloadType, Flags
from wapitiCore.language.vulnerability import Messages, CRITICAL_LEVEL, _
from wapitiCore.definitions.ssrf import NAME
from wapitiCore.net.web import Request

SSRF_PAYLOAD = "{external_endpoint}ssrf/{random_id}/{path_id}/{hex_param}/"


class SsrfMutator(Mutator):
    def __init__(
            self, session_id: str, methods="FGP", payloads=None, qs_inject=False, max_queries_per_pattern: int = 1000,
            parameters=None,  # Restrict attack to a whitelist of parameters
            skip=None,  # Must not attack those parameters (blacklist)
            endpoint: str = "http://wapiti3.ovh/"
    ):
        Mutator.__init__(
            self, methods=methods, payloads=payloads, qs_inject=qs_inject,
            max_queries_per_pattern=max_queries_per_pattern, parameters=parameters, skip=skip)
        self._session_id = session_id
        self._endpoint = endpoint

    def mutate(self, request: Request):
        get_params = request.get_params
        post_params = request.post_params
        file_params = request.file_params
        referer = request.referer

        # estimation = self.estimate_requests_count(request)
        #
        # if self._attacks_per_url_pattern[request.hash_params] + estimation > self._max_queries_per_pattern:
        #     # Otherwise (pattern already attacked), make sure we don't exceed maximum allowed
        #     return
        #
        # self._attacks_per_url_pattern[request.hash_params] += estimation

        for params_list in [get_params, post_params, file_params]:
            for i in range(len(params_list)):
                param_name = quote(params_list[i][0])

                if self._skip_list and param_name in self._skip_list:
                    continue

                if self._parameters and param_name not in self._parameters:
                    continue

                saved_value = params_list[i][1]
                if saved_value is None:
                    saved_value = ""

                if params_list is file_params:
                    params_list[i][1] = ("__PAYLOAD__", saved_value[1], saved_value[2])
                else:
                    params_list[i][1] = "__PAYLOAD__"

                attack_pattern = Request(
                    request.path,
                    method=request.method,
                    get_params=get_params,
                    post_params=post_params,
                    file_params=file_params
                )

                if hash(attack_pattern) not in self._attack_hashes:
                    self._attack_hashes.add(hash(attack_pattern))

                    payload = SSRF_PAYLOAD.format(
                        external_endpoint=self._endpoint,
                        random_id=self._session_id,
                        path_id=request.path_id,
                        hex_param=hexlify(param_name.encode("utf-8", errors="replace")).decode()
                    )

                    if params_list is file_params:
                        params_list[i][1] = (payload, saved_value[1], saved_value[2])
                        method = PayloadType.file
                    else:
                        params_list[i][1] = payload
                        if params_list is get_params:
                            method = PayloadType.get
                        else:
                            method = PayloadType.post

                    evil_req = Request(
                        request.path,
                        method=request.method,
                        get_params=get_params,
                        post_params=post_params,
                        file_params=file_params,
                        referer=referer,
                        link_depth=request.link_depth
                    )
                    yield evil_req, param_name, payload, Flags(method=method)

                params_list[i][1] = saved_value

        if not get_params and request.method == "GET" and self._qs_inject:
            attack_pattern = Request(
                "{}?__PAYLOAD__".format(request.path),
                method=request.method,
                referer=referer,
                link_depth=request.link_depth
            )

            if hash(attack_pattern) not in self._attack_hashes:
                self._attack_hashes.add(hash(attack_pattern))

                payload = SSRF_PAYLOAD.format(
                    external_endpoint=self._endpoint,
                    random_id=self._session_id,
                    path_id=request.path_id,
                    hex_param=hexlify(b"QUERY_STRING").decode()
                )

                evil_req = Request(
                    "{}?{}".format(request.path, quote(payload)),
                    method=request.method,
                    referer=referer,
                    link_depth=request.link_depth
                )

                yield evil_req, "QUERY_STRING", payload, Flags(method=PayloadType.get)


class mod_ssrf(Attack):
    """
    Detect Server-Side Request Forgery vulnerabilities.
    """

    name = "ssrf"
    MSG_VULN = _("SSRF vulnerability")

    def __init__(self, crawler, persister, logger, attack_options, stop_event):
        super().__init__(crawler, persister, logger, attack_options, stop_event)

        methods = ""
        if self.do_get:
            methods += "G"
        if self.do_post:
            methods += "PF"

        self.mutator = SsrfMutator(
            session_id=self._session_id,
            methods=methods,
            payloads=self.payloads,
            qs_inject=self.must_attack_query_string,
            skip=self.options.get("skipped_parameters"),
            endpoint=self.external_endpoint
        )

    async def attack(self, request: Request):
        # Let's just send payloads, we don't care of the response as what we want to know is if the target
        # contacted the endpoint.
        for mutated_request, _parameter, _payload, _flags in self.mutator.mutate(request):
            if self.verbose == 2:
                print("[¨] {0}".format(mutated_request))

            try:
                await self.crawler.async_send(mutated_request)
            except RequestError:
                self.network_errors += 1
                continue

    async def finish(self):
        endpoint_url = "{}get_ssrf.php?session_id={}".format(self.internal_endpoint, self._session_id)
        print(_("[*] Asking endpoint URL {} for results, please wait...").format(endpoint_url))
        await sleep(2)
        # A la fin des attaques on questionne le endpoint pour savoir s'il a été contacté
        endpoint_request = Request(endpoint_url)
        try:
            response = await self.crawler.async_send(endpoint_request)
        except RequestError:
            self.network_errors += 1
            print(_("[!] Unable to request endpoint URL '{}'").format(self.internal_endpoint))
        else:
            data = response.json
            if isinstance(data, dict):
                for request_id in data:
                    original_request = self.persister.get_path_by_id(request_id)
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
                                vuln_message = _(
                                    "{0} via injection in the parameter {1}.\n"
                                    "The target performed an outgoing HTTP {2} request at {3} with IP {4}.\n"
                                    "Full request can be seen at {5}"
                                ).format(
                                    self.MSG_VULN,
                                    parameter,
                                    request_method,
                                    request_date,
                                    request_ip,
                                    request_url
                                )

                            mutator = Mutator(
                                methods="G" if original_request.method == "GET" else "PF",
                                payloads=[("http://external.url/page", Flags())],
                                qs_inject=self.must_attack_query_string,
                                parameters=[parameter],
                                skip=self.options.get("skipped_parameters")
                            )

                            mutated_request, __, __, __ = next(mutator.mutate(original_request))

                            self.add_vuln(
                                request_id=original_request.path_id,
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
                                self.MSG_VULN,
                                page,
                                parameter
                            )
                            self.log_red(Messages.MSG_EVIL_REQUEST)
                            self.log_red(mutated_request.http_repr())
                            self.log_red("---")
