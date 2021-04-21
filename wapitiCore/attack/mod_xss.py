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
from configparser import ConfigParser

from httpx import ReadTimeout, RequestError

from wapitiCore.attack.attack import Attack, Mutator, PayloadType, random_string_with_flags
from wapitiCore.language.vulnerability import Messages, HIGH_LEVEL, MEDIUM_LEVEL, _
from wapitiCore.definitions.xss import NAME
from wapitiCore.net.xss_utils import generate_payloads, valid_xss_content_type, find_non_exec_parent
from wapitiCore.net.csp_utils import has_strong_csp
from wapitiCore.net.web import Request


class mod_xss(Attack):
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

    def __init__(self, crawler, persister, logger, attack_options, stop_event):
        Attack.__init__(self, crawler, persister, logger, attack_options, stop_event)
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
            if self.verbose == 2:
                print("[¨] {0}".format(evil_request))

            try:
                response = await self.crawler.async_send(evil_request)
            except ReadTimeout:
                self.network_errors += 1
                if timeouted:
                    continue

                self.log_orange("---")
                self.log_orange(Messages.MSG_TIMEOUT, page)
                self.log_orange(Messages.MSG_EVIL_REQUEST)
                self.log_orange(evil_request.http_repr())
                self.log_orange("---")

                if xss_param == "QUERY_STRING":
                    anom_msg = Messages.MSG_QS_TIMEOUT
                else:
                    anom_msg = Messages.MSG_PARAM_TIMEOUT.format(xss_param)

                self.add_anom(
                    request_id=original_request.path_id,
                    category=Messages.RES_CONSUMPTION,
                    level=MEDIUM_LEVEL,
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
                        self.check_payload(response, xss_flags, taint)
                ):
                    self.successful_xss[taint] = (xss_payload, xss_flags)
                    message = _("XSS vulnerability found via injection in the parameter {0}").format(xss_param)
                    if has_strong_csp(response):
                        message += ".\n" + _("Warning: Content-Security-Policy is present!")

                    self.add_vuln(
                        request_id=original_request.path_id,
                        category=NAME,
                        level=MEDIUM_LEVEL,
                        request=evil_request,
                        parameter=xss_param,
                        info=message
                    )

                    if xss_param == "QUERY_STRING":
                        injection_msg = Messages.MSG_QS_INJECT
                    else:
                        injection_msg = Messages.MSG_PARAM_INJECT

                    self.log_red("---")
                    self.log_red(
                        injection_msg,
                        self.MSG_VULN,
                        page,
                        xss_param
                    )

                    if has_strong_csp(response):
                        self.log_red(_("Warning: Content-Security-Policy is present!"))

                    self.log_red(Messages.MSG_EVIL_REQUEST)
                    self.log_red(evil_request.http_repr())
                    self.log_red("---")

                    # stop trying payloads and jump to the next parameter
                    break

                if response.status == 500 and not saw_internal_error:
                    if xss_param == "QUERY_STRING":
                        anom_msg = Messages.MSG_QS_500
                    else:
                        anom_msg = Messages.MSG_PARAM_500.format(xss_param)

                    self.add_anom(
                        request_id=original_request.path_id,
                        category=Messages.ERROR_500,
                        level=HIGH_LEVEL,
                        request=evil_request,
                        info=anom_msg,
                        parameter=xss_param
                    )

                    self.log_orange("---")
                    self.log_orange(Messages.MSG_500, page)
                    self.log_orange(Messages.MSG_EVIL_REQUEST)
                    self.log_orange(evil_request.http_repr())
                    self.log_orange("---")
                    saw_internal_error = True

    def check_payload(self, response, flags, taint):
        config_reader = ConfigParser(interpolation=None)
        config_reader.read_file(open(path_join(self.DATA_DIR, self.PAYLOADS_FILE)))

        for section in config_reader.sections():
            if section == flags.section:
                expected_value = config_reader[section]["value"].replace('[EXTERNAL_ENDPOINT]', self.external_endpoint)
                expected_value = expected_value.replace("__XSS__", taint)
                tag_names = config_reader[section]["tag"].split(",")
                attribute = config_reader[section]["attribute"]
                case_sensitive = config_reader[section].getboolean("case_sensitive")
                match_type = config_reader[section].get("match_type", "exact")

                attribute_constraint = {attribute: True} if attribute not in ["full_string", "string"] else {}

                for tag in response.soup.find_all(tag_names, attrs=attribute_constraint):
                    non_exec_parent = find_non_exec_parent(tag)

                    if non_exec_parent and not (tag.name == "frame" and non_exec_parent == "frameset"):
                        continue

                    if attribute == "string" and tag.string:
                        if case_sensitive:
                            if expected_value in tag.string:
                                return True
                        else:
                            if expected_value.lower() in tag.string.lower():
                                return True
                    elif attribute == "full_string" and tag.string:
                        if case_sensitive:
                            if match_type == "exact" and expected_value == tag.string.strip():
                                return True
                            if match_type == "starts_with" and tag.string.strip().startswith(expected_value):
                                return True
                        else:
                            if match_type == "exact" and expected_value.lower() == tag.string.strip().lower():
                                return True
                            if match_type == "starts_with" and \
                                    tag.string.strip().lower().startswith(expected_value.lower()):
                                return True
                    else:
                        # Found attribute specified in .ini file in attributes of the HTML tag
                        if attribute in tag.attrs:
                            if case_sensitive:
                                if match_type == "exact" and tag[attribute] == expected_value:
                                    return True
                                if match_type == "starts_with" and tag[attribute].startswith(expected_value):
                                    return True
                            else:
                                if match_type == "exact" and tag[attribute].lower() == expected_value.lower():
                                    return True
                                if match_type == "starts_with" and \
                                        expected_value.lower().startswith(tag[attribute].lower()):
                                    return True
                break

        return False
