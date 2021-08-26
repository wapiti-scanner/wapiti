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
from urllib.parse import quote
from configparser import ConfigParser
from os.path import join as path_join

from httpx import ReadTimeout, RequestError
from wapitiCore.main.log import logging

from wapitiCore.attack.attack import Attack, PayloadType, Mutator
from wapitiCore.language.vulnerability import Messages, _
from wapitiCore.definitions.xss import NAME
from wapitiCore.net.web import Request
from wapitiCore.net.xss_utils import generate_payloads, valid_xss_content_type, find_non_exec_parent
from wapitiCore.net.csp_utils import has_strong_csp


class mod_permanentxss(Attack):
    """
    Detect stored (aka permanent) Cross-Site Scripting vulnerabilities on the web server.
    """

    name = "permanentxss"
    require = ["xss"]
    PRIORITY = 6

    # Attempted payload injection from mod_xss.
    # key is tainted value, dict values are (mutated_request, parameter, flags)
    tried_xss = {}

    # key = xss code, valid = (payload, flags)
    successful_xss = {}

    PAYLOADS_FILE = path_join(Attack.DATA_DIR, "xssPayloads.ini")

    MSG_VULN = _("Stored XSS vulnerability")

    async def must_attack(self, request: Request):
        if not valid_xss_content_type(request) or request.status in (301, 302, 303):
            # If that content-type can't be interpreted as HTML by browsers then it is useless
            # Same goes for redirections
            return False

        return True

    async def attack(self, request: Request):
        """This method searches XSS which could be permanently stored in the web application"""
        url = request.url
        target_req = Request(url)
        referer = request.referer
        headers = {}

        if referer:
            headers["referer"] = referer

        try:
            response = await self.crawler.async_send(target_req, headers=headers)
            data = response.content
        except RequestError:
            self.network_errors += 1
            return

        # Should we look for taint codes sent with GET in the webpages?
        # Exploiting those may imply sending more GET requests

        # Search in the page source for every taint code used by mod_xss
        for taint in self.tried_xss:
            input_request = self.tried_xss[taint][0]

            # Such situations should not occur as it would be stupid to block POST (or GET) requests for mod_xss
            # and not mod_permanentxss, but it is possible so let's filter that.
            if not self.do_get and input_request.method == "GET":
                continue

            if not self.do_post and input_request.method == "POST":
                continue

            if taint.lower() in data.lower():
                # Code found in the webpage !
                # Did mod_xss saw this as a reflected XSS ?
                if taint in self.successful_xss:
                    # Yes, it means XSS payloads were injected, not just tainted code.
                    payload, flags = self.successful_xss[taint]

                    if self.check_payload(response, flags, taint):
                        # If we can find the payload again, this is in fact a stored XSS
                        get_params = input_request.get_params
                        post_params = input_request.post_params
                        file_params = input_request.file_params
                        referer = input_request.referer

                        # The following trick may seems dirty but it allows to treat GET and POST requests
                        # the same way.
                        for params_list in [get_params, post_params, file_params]:
                            for i, __ in enumerate(params_list):
                                parameter, value = params_list[i]
                                parameter = quote(parameter)
                                if value != taint:
                                    continue

                                if params_list is file_params:
                                    params_list[i][1][0] = payload
                                else:
                                    params_list[i][1] = payload

                                # we found the xss payload again -> stored xss vuln
                                evil_request = Request(
                                    input_request.path,
                                    method=input_request.method,
                                    get_params=get_params,
                                    post_params=post_params,
                                    file_params=file_params,
                                    referer=referer
                                )

                                if request.path == input_request.path:
                                    description = _(
                                        "Permanent XSS vulnerability found via injection in the parameter {0}"
                                    ).format(parameter)
                                else:
                                    description = _(
                                        "Permanent XSS vulnerability found in {0} by injecting"
                                        " the parameter {1} of {2}"
                                    ).format(
                                        request.url,
                                        parameter,
                                        input_request.path
                                    )

                                if has_strong_csp(response):
                                    description += ".\n" + _("Warning: Content-Security-Policy is present!")

                                await self.add_vuln_high(
                                    request_id=request.path_id,
                                    category=NAME,
                                    request=evil_request,
                                    parameter=parameter,
                                    info=description
                                )

                                if parameter == "QUERY_STRING":
                                    injection_msg = Messages.MSG_QS_INJECT
                                else:
                                    injection_msg = Messages.MSG_PARAM_INJECT

                                self.log_red("---")
                                self.log_red(
                                    injection_msg,
                                    self.MSG_VULN,
                                    request.path,
                                    parameter
                                )

                                if has_strong_csp(response):
                                    self.log_red(_("Warning: Content-Security-Policy is present!"))

                                self.log_red(Messages.MSG_EVIL_REQUEST)
                                self.log_red(evil_request.http_repr())
                                self.log_red("---")
                                # FIX: search for the next code in the webpage

                # Ok the content is stored, but will we be able to inject javascript?
                else:
                    parameter = self.tried_xss[taint][1]
                    payloads = generate_payloads(response.content, taint, self.PAYLOADS_FILE, self.external_endpoint)
                    flags = self.tried_xss[taint][2]

                    # TODO: check that and make it better
                    if flags.method == PayloadType.get:
                        method = "G"
                    elif flags.method == PayloadType.file:
                        method = "F"
                    else:
                        method = "P"

                    await self.attempt_exploit(method, payloads, input_request, parameter, taint, request)

    def load_require(self, dependencies: list = None):
        if dependencies:
            for module in dependencies:
                if module.name == "xss":
                    self.successful_xss = module.successful_xss
                    self.tried_xss = module.tried_xss

    async def attempt_exploit(self, method, payloads, injection_request, parameter, taint, output_request):
        timeouted = False
        page = injection_request.path
        saw_internal_error = False
        output_url = output_request.url

        attack_mutator = Mutator(
            methods=method,
            payloads=payloads,
            qs_inject=self.must_attack_query_string,
            parameters=[parameter],
            skip=self.options.get("skipped_parameters")
        )

        for evil_request, xss_param, _xss_payload, xss_flags in attack_mutator.mutate(injection_request):
            if self.verbose == 2:
                logging.info("[¨] {0}".format(evil_request))

            try:
                await self.crawler.async_send(evil_request)
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

                await self.add_anom_medium(
                    request_id=injection_request.path_id,
                    category=Messages.RES_CONSUMPTION,
                    request=evil_request,
                    info=anom_msg,
                    parameter=xss_param
                )
                timeouted = True
            except RequestError:
                self.network_errors += 1
                continue
            else:
                try:
                    response = await self.crawler.async_send(output_request)
                except RequestError:
                    self.network_errors += 1
                    continue

                if (
                        response.status not in (301, 302, 303) and
                        valid_xss_content_type(evil_request) and
                        self.check_payload(response, xss_flags, taint)
                ):

                    if page == output_request.path:
                        description = _(
                            "Permanent XSS vulnerability found via injection in the parameter {0}"
                        ).format(xss_param)
                    else:
                        description = _(
                            "Permanent XSS vulnerability found in {0} by injecting"
                            " the parameter {1} of {2}"
                        ).format(
                            output_request.url,
                            parameter,
                            page
                        )

                    if has_strong_csp(response):
                        description += ".\n" + _("Warning: Content-Security-Policy is present!")

                    await self.add_vuln_high(
                        request_id=injection_request.path_id,
                        category=NAME,
                        request=evil_request,
                        parameter=xss_param,
                        info=description
                    )

                    if xss_param == "QUERY_STRING":
                        injection_msg = Messages.MSG_QS_INJECT
                    else:
                        injection_msg = Messages.MSG_PARAM_INJECT

                    self.log_red("---")
                    # TODO: a last parameter should give URL used to pass the vulnerable parameter
                    self.log_red(
                        injection_msg,
                        self.MSG_VULN,
                        output_url,
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

                    await self.add_anom_high(
                        request_id=injection_request.path_id,
                        category=Messages.ERROR_500,
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
        with open(path_join(self.DATA_DIR, self.PAYLOADS_FILE)) as payload_file:
            config_reader.read_file(payload_file)

        for section in config_reader.sections():
            if section == flags.section:
                expected_value = config_reader[section]["value"].replace("__XSS__", taint)
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
