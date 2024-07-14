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
from os.path import join as path_join
from typing import Optional, Iterator, List, Tuple, Dict

from httpx import ReadTimeout, RequestError

from wapitiCore.main.log import log_orange, log_red, log_verbose
from wapitiCore.attack.attack import Attack, Mutator, ParameterSituation, random_string, Parameter
from wapitiCore.language.vulnerability import Messages
from wapitiCore.definitions.reflected_xss import XssFinding
from wapitiCore.definitions.html_injection import HtmlInjectionFinding
from wapitiCore.definitions.resource_consumption import ResourceConsumptionFinding
from wapitiCore.definitions.internal_error import InternalErrorFinding
from wapitiCore.model import PayloadInfo
from wapitiCore.net.xss_utils import generate_payloads, valid_xss_content_type, check_payload
from wapitiCore.net.csp_utils import has_strong_csp
from wapitiCore.net import Request, Response
from wapitiCore.parsers.html_parser import Html


def get_random_string_payload(_: Request, __: Parameter) -> Iterator[PayloadInfo]:
    yield PayloadInfo(payload=random_string())


class ModuleXss(Attack):
    """Detects stored (aka permanent) Cross-Site Scripting vulnerabilities on the web server."""

    name = "xss"

    # two dict exported for permanent XSS scanning
    # GET_XSS structure :
    # {uniq_code : http://url/?param1=value1&param2=uniq_code&param3..., next_uniq_code : ...}
    # GET_XSS = {}
    # POST XSS structure :
    # {uniq_code: [target_url, {param1: val1, param2: uniq_code, param3:...}, referer_ul], next_uniq_code : [...]...}
    # POST_XSS = {}
    tried_xss: Dict[str, Tuple[Request, Parameter]] = {}
    PHP_SELF = []

    # key = taint code, value = (evil request, payload info)
    successful_xss: Dict[str, Tuple[Request, PayloadInfo]] = {}

    PAYLOADS_FILE = path_join(Attack.DATA_DIR, "xssPayloads.ini")

    RANDOM_WEBSITE = f"https://{random_string(length=6)}.com/"

    def __init__(self, crawler, persister, attack_options, stop_event, crawler_configuration):
        Attack.__init__(self, crawler, persister, attack_options, stop_event, crawler_configuration)
        methods = ""
        if self.do_get:
            methods += "G"
        if self.do_post:
            methods += "PF"

        self.mutator = Mutator(
            methods=methods,
            qs_inject=self.must_attack_query_string,
            skip=self.options.get("skipped_parameters")
        )

    @property
    def external_endpoint(self):
        return self.RANDOM_WEBSITE

    async def attack(self, request: Request, response: Optional[Response] = None):
        for mutated_request, parameter, payload_info in self.mutator.mutate(
                request,
                get_random_string_payload
        ):
            # We don't display the mutated request here as the payload is not interesting
            try:
                response = await self.crawler.async_send(mutated_request)
            except RequestError:
                self.network_errors += 1
                # We just inserted harmless characters, if we get a timeout here, it's not interesting
                continue
            else:
                # We keep a history of taint values we sent because in case of stored value, the taint code
                # may be found in another webpage by the permanentxss module.
                self.tried_xss[payload_info.payload] = (request, parameter)

                # Reminder: valid_xss_content_type is not called before before content is not necessary
                # reflected here, may be found in another webpage so we have to inject tainted values
                # even if the Content-Type seems uninteresting.
                if payload_info.payload.lower() in response.content.lower() and valid_xss_content_type(response):
                    # Simple text injection worked in HTML response, let's try with JS code
                    payloads = generate_payloads(
                        response.content,
                        payload_info.payload,
                        self.PAYLOADS_FILE,
                        self.external_endpoint
                    )

                    if parameter.situation == ParameterSituation.QUERY_STRING:
                        method = "G"
                    elif parameter.situation == ParameterSituation.MULTIPART:
                        method = "F"
                    else:
                        method = "P"

                    await self.attempt_exploit(method, payloads, request, parameter.name, payload_info.payload)

    async def attempt_exploit(
            self, method: str, payloads: List[PayloadInfo], original_request: Request, parameter: str, taint: str
    ):
        timeouted = False
        page = original_request.path
        saw_internal_error = False

        attack_mutator = Mutator(
            methods=method,
            qs_inject=self.must_attack_query_string,
            parameters=[parameter],
            skip=self.options.get("skipped_parameters")
        )

        for evil_request, xss_param, xss_payload in attack_mutator.mutate(
                original_request,
                payloads,
        ):
            log_verbose(f"[¨] {evil_request}")

            try:
                response = await self.crawler.async_send(evil_request)
            except ReadTimeout:
                self.network_errors += 1
                if timeouted:
                    continue

                log_orange("---")
                log_orange(Messages.MSG_TIMEOUT, page)
                log_orange(Messages.MSG_EVIL_REQUEST)
                log_orange(evil_request.http_repr())
                log_orange("---")

                if xss_param.is_qs_injection:
                    anom_msg = Messages.MSG_QS_TIMEOUT
                else:
                    anom_msg = Messages.MSG_PARAM_TIMEOUT.format(xss_param.name)

                await self.add_medium(
                    request_id=original_request.path_id,
                    finding_class=ResourceConsumptionFinding,
                    request=evil_request,
                    info=anom_msg,
                    parameter=xss_param.name,
                )
                timeouted = True
            except RequestError:
                self.network_errors += 1
            else:
                html = Html(response.content, evil_request.url)
                if (
                        not response.is_redirect and
                        valid_xss_content_type(response) and
                        check_payload(
                            self.DATA_DIR,
                            self.PAYLOADS_FILE,
                            self.external_endpoint,
                            self.proto_endpoint,
                            html,
                            xss_payload,
                            taint
                        )
                ):
                    self.successful_xss[taint] = (evil_request, xss_payload)
                    finding = XssFinding if xss_payload.injection_type == "javascript" else HtmlInjectionFinding
                    message = f"{finding.name()} vulnerability found via injection in the parameter {xss_param.name}"
                    if has_strong_csp(response, html):
                        message += ".\nWarning: Content-Security-Policy is present!"

                    await self.add_medium(
                        request_id=original_request.path_id,
                        finding_class=finding,
                        request=evil_request,
                        parameter=xss_param.name,
                        info=message,
                        response=response
                    )

                    if xss_param.is_qs_injection:
                        injection_msg = Messages.MSG_QS_INJECT
                    else:
                        injection_msg = Messages.MSG_PARAM_INJECT

                    log_red("---")
                    log_red(
                        injection_msg,
                        finding.name(),
                        page,
                        xss_param.name
                    )

                    if has_strong_csp(response, html):
                        log_red("Warning: Content-Security-Policy is present!")

                    log_red(Messages.MSG_EVIL_REQUEST)
                    log_red(evil_request.http_repr())
                    log_red("---")

                    # stop trying payloads and jump to the next parameter
                    break

                if response.is_server_error and not saw_internal_error:
                    if xss_param.is_qs_injection:
                        anom_msg = Messages.MSG_QS_500
                    else:
                        anom_msg = Messages.MSG_PARAM_500.format(xss_param.name)

                    await self.add_high(
                        request_id=original_request.path_id,
                        finding_class=InternalErrorFinding,
                        request=evil_request,
                        info=anom_msg,
                        parameter=xss_param.name,
                        response=response
                    )

                    log_orange("---")
                    log_orange(Messages.MSG_500, page)
                    log_orange(Messages.MSG_EVIL_REQUEST)
                    log_orange(evil_request.http_repr())
                    log_orange("---")
                    saw_internal_error = True
