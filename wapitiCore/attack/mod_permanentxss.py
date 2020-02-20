#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (http://wapiti.sourceforge.io)
# Copyright (C) 2008-2020 Nicolas Surribas
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
from math import ceil

from requests.exceptions import Timeout, ReadTimeout

from wapitiCore.attack.attack import Attack, PayloadType, Mutator
from wapitiCore.language.vulnerability import Vulnerability, Anomaly, _
from wapitiCore.net import web
from wapitiCore.net.xss_utils import generate_payloads, valid_xss_content_type, find_non_exec_parent, has_csp


class mod_permanentxss(Attack):
    """
    This class detects permanent (stored) XSS vulnerabilities.
    """

    # simple payloads that doesn't rely on their position in the DOM structure
    # payloads injected after closing a tag attribute value (attrval) or in the
    # content of a tag (text node like between <p> and </p>)
    # only trick here must be on character encoding, filter bypassing, stuff like that
    # form the simplest to the most complex, Wapiti will stop on the first working
    independant_payloads = []

    name = "permanentxss"
    require = ["xss"]
    PRIORITY = 6

    # Attempted payload injection from mod_xss.
    # key is tainted value, dict values are (mutated_request, parameter, flags)
    TRIED_XSS = {}

    # key = xss code, valid = (payload, flags)
    SUCCESSFUL_XSS = {}

    PAYLOADS_FILE = "xssPayloads.ini"

    MSG_VULN = _("Stored XSS vulnerability")

    def __init__(self, crawler, persister, logger, attack_options):
        Attack.__init__(self, crawler, persister, logger, attack_options)
        self.independant_payloads = self.payloads

    def attack(self):
        """This method searches XSS which could be permanently stored in the web application"""
        get_resources = self.persister.get_links(attack_module=self.name) if self.do_get else []

        for original_request in get_resources:
            if not valid_xss_content_type(original_request) or original_request.status in (301, 302, 303):
                # If that content-type can't be interpreted as HTML by browsers then it is useless
                # Same goes for redirections
                continue

            url = original_request.url
            target_req = web.Request(url)
            referer = original_request.referer
            headers = {}

            if referer:
                headers["referer"] = referer
            if self.verbose >= 1:
                print("[+] {}".format(url))

            try:
                response = self.crawler.send(target_req, headers=headers)
                data = response.content
            except Timeout:
                continue
            except OSError as exception:
                # TODO: those error messages are useless, don't give any valuable information
                print(_("error: {0} while attacking {1}").format(exception.strerror, url))
                continue
            except Exception as exception:
                print(_("error: {0} while attacking {1}").format(exception, url))
                continue

            # Should we look for taint codes sent with GET in the webpages?
            # Exploiting those may imply sending more GET requests

            # Search in the page source for every taint code used by mod_xss
            for taint in self.TRIED_XSS:
                input_request = self.TRIED_XSS[taint][0]

                # Such situations should not occur as it would be stupid to block POST (or GET) requests for mod_xss
                # and not mod_permanentxss, but it is possible so let's filter that.
                if not self.do_get and input_request.method == "GET":
                    continue

                if not self.do_post and input_request.method == "POST":
                    continue

                if taint.lower() in data.lower():
                    # Code found in the webpage !
                    # Did mod_xss saw this as a reflected XSS ?
                    if taint in self.SUCCESSFUL_XSS:
                        # Yes, it means XSS payloads were injected, not just tainted code.
                        payload, flags = self.SUCCESSFUL_XSS[taint]

                        if self.check_payload(response, flags, taint):
                            # If we can find the payload again, this is in fact a stored XSS
                            get_params = input_request.get_params
                            post_params = input_request.post_params
                            file_params = input_request.file_params
                            referer = input_request.referer

                            # The following trick may seems dirty but it allows to treat GET and POST requests
                            # the same way.
                            for params_list in [get_params, post_params, file_params]:
                                for i in range(len(params_list)):
                                    parameter, value = params_list[i]
                                    parameter = quote(parameter)
                                    if value != taint:
                                        continue

                                    if params_list is file_params:
                                        params_list[i][1][0] = payload
                                    else:
                                        params_list[i][1] = payload

                                    # we found the xss payload again -> stored xss vuln
                                    evil_request = web.Request(
                                        input_request.path,
                                        method=input_request.method,
                                        get_params=get_params,
                                        post_params=post_params,
                                        file_params=file_params,
                                        referer=referer
                                    )

                                    if original_request.path == input_request.path:
                                        description = _(
                                            "Permanent XSS vulnerability found via injection in the parameter {0}"
                                        ).format(parameter)
                                    else:
                                        description = _(
                                            "Permanent XSS vulnerability found in {0} by injecting"
                                            " the parameter {1} of {2}"
                                        ).format(
                                            original_request.url,
                                            parameter,
                                            input_request.path
                                        )

                                    if has_csp(response):
                                        description += ".\n" + _("Warning: Content-Security-Policy is present!")

                                    self.add_vuln(
                                        request_id=original_request.path_id,
                                        category=Vulnerability.XSS,
                                        level=Vulnerability.HIGH_LEVEL,
                                        request=evil_request,
                                        parameter=parameter,
                                        info=description
                                    )

                                    if parameter == "QUERY_STRING":
                                        injection_msg = Vulnerability.MSG_QS_INJECT
                                    else:
                                        injection_msg = Vulnerability.MSG_PARAM_INJECT

                                    self.log_red("---")
                                    self.log_red(
                                        injection_msg,
                                        self.MSG_VULN,
                                        original_request.path,
                                        parameter
                                    )

                                    if has_csp(response):
                                        self.log_red(_("Warning: Content-Security-Policy is present!"))

                                    self.log_red(Vulnerability.MSG_EVIL_REQUEST)
                                    self.log_red(evil_request.http_repr())
                                    self.log_red("---")
                                    # FIX: search for the next code in the webpage

                    # Ok the content is stored, but will we be able to inject javascript?
                    else:
                        parameter = self.TRIED_XSS[taint][1]
                        payloads = generate_payloads(response.content, taint, self.independant_payloads)
                        flags = self.TRIED_XSS[taint][2]

                        # TODO: check that and make it better
                        if PayloadType.get in flags:
                            method = "G"
                        elif PayloadType.file in flags:
                            method = "F"
                        else:
                            method = "P"

                        self.attempt_exploit(method, payloads, input_request, parameter, taint, original_request)

            yield original_request

    def load_require(self, dependencies: list = None):
        if dependencies:
            for module in dependencies:
                if module.name == "xss":
                    self.SUCCESSFUL_XSS = module.SUCCESSFUL_XSS
                    self.TRIED_XSS = module.TRIED_XSS

    def attempt_exploit(self, method, payloads, injection_request, parameter, taint, output_request):
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

        for evil_request, xss_param, xss_payload, xss_flags in attack_mutator.mutate(injection_request):
            if self.verbose == 2:
                print("[¨] {0}".format(evil_request))

            try:
                self.crawler.send(evil_request)
            except ReadTimeout:
                if timeouted:
                    continue

                self.log_orange("---")
                self.log_orange(Anomaly.MSG_TIMEOUT, page)
                self.log_orange(Anomaly.MSG_EVIL_REQUEST)
                self.log_orange(evil_request.http_repr())
                self.log_orange("---")

                if xss_param == "QUERY_STRING":
                    anom_msg = Anomaly.MSG_QS_TIMEOUT
                else:
                    anom_msg = Anomaly.MSG_PARAM_TIMEOUT.format(xss_param)

                self.add_anom(
                    request_id=injection_request.path_id,
                    category=Anomaly.RES_CONSUMPTION,
                    level=Anomaly.MEDIUM_LEVEL,
                    request=evil_request,
                    info=anom_msg,
                    parameter=xss_param
                )
                timeouted = True

            else:
                try:
                    response = self.crawler.send(output_request)
                except ReadTimeout:
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

                    if has_csp(response):
                        description += ".\n" + _("Warning: Content-Security-Policy is present!")

                    self.add_vuln(
                        request_id=injection_request.path_id,
                        category=Vulnerability.XSS,
                        level=Vulnerability.HIGH_LEVEL,
                        request=evil_request,
                        parameter=xss_param,
                        info=description
                    )

                    if xss_param == "QUERY_STRING":
                        injection_msg = Vulnerability.MSG_QS_INJECT
                    else:
                        injection_msg = Vulnerability.MSG_PARAM_INJECT

                    self.log_red("---")
                    # TODO: a last parameter should give URL used to pass the vulnerable parameter
                    self.log_red(
                        injection_msg,
                        self.MSG_VULN,
                        output_url,
                        xss_param
                    )

                    if has_csp(response):
                        self.log_red(_("Warning: Content-Security-Policy is present!"))

                    self.log_red(Vulnerability.MSG_EVIL_REQUEST)
                    self.log_red(evil_request.http_repr())
                    self.log_red("---")

                    # stop trying payloads and jump to the next parameter
                    break
                elif response.status == 500 and not saw_internal_error:
                    if xss_param == "QUERY_STRING":
                        anom_msg = Anomaly.MSG_QS_500
                    else:
                        anom_msg = Anomaly.MSG_PARAM_500.format(xss_param)

                    self.add_anom(
                        request_id=injection_request.path_id,
                        category=Anomaly.ERROR_500,
                        level=Anomaly.HIGH_LEVEL,
                        request=evil_request,
                        info=anom_msg,
                        parameter=xss_param
                    )

                    self.log_orange("---")
                    self.log_orange(Anomaly.MSG_500, page)
                    self.log_orange(Anomaly.MSG_EVIL_REQUEST)
                    self.log_orange(evil_request.http_repr())
                    self.log_orange("---")
                    saw_internal_error = True

    @property
    def payloads(self):
        """Load the payloads from the specified file"""
        if not self.PAYLOADS_FILE:
            return []

        payloads = []

        config_reader = ConfigParser(interpolation=None)
        config_reader.read_file(open(path_join(self.CONFIG_DIR, self.PAYLOADS_FILE)))

        for section in config_reader.sections():
            payload = config_reader[section]["payload"]
            flags = {section}

            clean_payload = payload.strip(" \n")
            clean_payload = clean_payload.replace("[TAB]", "\t")
            clean_payload = clean_payload.replace("[LF]", "\n")
            clean_payload = clean_payload.replace(
                "[TIME]",
                str(int(ceil(self.options["timeout"])) + 1)
            )

            payload_type = PayloadType.pattern
            if "[TIMEOUT]" in clean_payload:
                payload_type = PayloadType.time
                clean_payload = clean_payload.replace("[TIMEOUT]", "")

            flags.add(payload_type)
            payloads.append((clean_payload, flags))

        return payloads

    def check_payload(self, response, flags, taint):
        config_reader = ConfigParser(interpolation=None)
        config_reader.read_file(open(path_join(self.CONFIG_DIR, self.PAYLOADS_FILE)))

        for section in config_reader.sections():
            if section in flags:
                expected_value = config_reader[section]["value"].replace("__XSS__", taint)
                attribute = config_reader[section]["attribute"]
                case_sensitive = config_reader[section].getboolean("case_sensitive")
                match_type = config_reader[section].get("match_type", "exact")

                for tag in response.soup.find_all(config_reader[section]["tag"]):
                    if find_non_exec_parent(tag):
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
                            elif match_type == "starts_with" and tag.string.strip().startswith(expected_value):
                                return True
                        else:
                            if match_type == "exact" and expected_value.lower() == tag.string.strip().lower():
                                return True
                            elif match_type == "starts_with" and \
                                    tag.string.strip().lower().startswith(expected_value.lower()):
                                return True
                    else:
                        # Found attribute specified in .ini file in attributes of the HTML tag
                        if attribute in tag.attrs:
                            if case_sensitive:
                                if match_type == "exact" and tag[attribute] == expected_value:
                                    return True
                                elif match_type == "starts_with" and tag[attribute].startswith(expected_value):
                                    return True
                            else:
                                if match_type == "exact" and tag[attribute].lower() == expected_value.lower():
                                    return True
                                elif match_type == "starts_with" and \
                                        expected_value.lower().startswith(tag[attribute].lower()):
                                    return True
                break

        return False
