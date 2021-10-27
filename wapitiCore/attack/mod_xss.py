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
from os.path import join as path_join

from httpx import ReadTimeout, RequestError

from wapitiCore.main.log import log_orange, log_red, log_verbose
from wapitiCore.attack.attack import Attack, Mutator, PayloadType, random_string_with_flags, random_string
from wapitiCore.language.vulnerability import Messages, _
from wapitiCore.definitions.xss import NAME
from wapitiCore.net.xss_utils import generate_payloads, valid_xss_content_type, check_payload
from wapitiCore.net.csp_utils import has_strong_csp
from wapitiCore.net.web import Request


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
    tried_xss = {}
    PHP_SELF = []

    # key = taint code, value = (payload, flags)
    successful_xss = {}

    PAYLOADS_FILE = path_join(Attack.DATA_DIR, "xssPayloads.ini")

    MSG_VULN = _("XSS vulnerability")

    RANDOM_WEBSITE = f"https://{random_string(length=6)}.com/"

    def __init__(self, crawler, persister, attack_options, stop_event):
        Attack.__init__(self, crawler, persister, attack_options, stop_event)
        methods = ""
        if self.do_get:
            methods += "G"
        if self.do_post:
            methods += "PF"

        self.mutator = Mutator(
            methods=methods,
            payloads=random_string_with_flags,
            qs_inject=self.must_attack_query_string,
            skip=self.options.get("skipped_parameters")
        )

    @property
    def external_endpoint(self):
        return self.RANDOM_WEBSITE

    async def attack(self, request: Request):
        for mutated_request, parameter, taint, flags in self.mutator.mutate(request):
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
                self.tried_xss[taint] = (mutated_request, parameter, flags)

                # Reminder: valid_xss_content_type is not called before before content is not necessary
                # reflected here, may be found in another webpage so we have to inject tainted values
                # even if the Content-Type seems uninteresting.
                if taint.lower() in response.content.lower() and valid_xss_content_type(mutated_request):
                    # Simple text injection worked in HTML response, let's try with JS code
                    payloads = generate_payloads(response.content, taint, self.PAYLOADS_FILE, self.external_endpoint)

                    # TODO: check that and make it better
                    if flags.method == PayloadType.get:
                        method = "G"
                    elif flags.method == PayloadType.file:
                        method = "F"
                    else:
                        method = "P"

                    await self.attempt_exploit(method, payloads, request, parameter, taint)

    async def attempt_exploit(self, method, payloads, original_request, parameter, taint):
        timeouted = False
        page = original_request.path
        saw_internal_error = False

        attack_mutator = Mutator(
            methods=method,
            payloads=payloads,
            qs_inject=self.must_attack_query_string,
            parameters=[parameter],
            skip=self.options.get("skipped_parameters")
        )

        for evil_request, xss_param, xss_payload, xss_flags in attack_mutator.mutate(original_request):
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

                if xss_param == "QUERY_STRING":
                    anom_msg = Messages.MSG_QS_TIMEOUT
                else:
                    anom_msg = Messages.MSG_PARAM_TIMEOUT.format(xss_param)

                await self.add_anom_medium(
                    request_id=original_request.path_id,
                    category=Messages.RES_CONSUMPTION,
                    request=evil_request,
                    info=anom_msg,
                    parameter=xss_param
                )
                timeouted = True
            except RequestError:
                self.network_errors += 1
            else:
                if (
                        response.status not in (301, 302, 303) and
                        valid_xss_content_type(evil_request) and
                        check_payload(
                            self.DATA_DIR,
                            self.PAYLOADS_FILE,
                            self.external_endpoint,
                            self.proto_endpoint,
                            response,
                            xss_flags,
                            taint
                        )
                ):
                    self.successful_xss[taint] = (xss_payload, xss_flags)
                    message = _("XSS vulnerability found via injection in the parameter {0}").format(xss_param)
                    if has_strong_csp(response):
                        message += ".\n" + _("Warning: Content-Security-Policy is present!")

                    await self.add_vuln_medium(
                        request_id=original_request.path_id,
                        category=NAME,
                        request=evil_request,
                        parameter=xss_param,
                        info=message
                    )

                    if xss_param == "QUERY_STRING":
                        injection_msg = Messages.MSG_QS_INJECT
                    else:
                        injection_msg = Messages.MSG_PARAM_INJECT

                    log_red("---")
                    log_red(
                        injection_msg,
                        self.MSG_VULN,
                        page,
                        xss_param
                    )

                    if has_strong_csp(response):
                        log_red(_("Warning: Content-Security-Policy is present!"))

                    log_red(Messages.MSG_EVIL_REQUEST)
                    log_red(evil_request.http_repr())
                    log_red("---")

                    # stop trying payloads and jump to the next parameter
                    break

                if response.status == 500 and not saw_internal_error:
                    if xss_param == "QUERY_STRING":
                        anom_msg = Messages.MSG_QS_500
                    else:
                        anom_msg = Messages.MSG_PARAM_500.format(xss_param)

                    await self.add_anom_high(
                        request_id=original_request.path_id,
                        category=Messages.ERROR_500,
                        request=evil_request,
                        info=anom_msg,
                        parameter=xss_param
                    )

                    log_orange("---")
                    log_orange(Messages.MSG_500, page)
                    log_orange(Messages.MSG_EVIL_REQUEST)
                    log_orange(evil_request.http_repr())
                    log_orange("---")
                    saw_internal_error = True
