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
import random
from itertools import chain
from os.path import join as path_join
from configparser import ConfigParser
from math import ceil

from requests.exceptions import ReadTimeout

from wapitiCore.attack.attack import Attack, Mutator, PayloadType
from wapitiCore.language.vulnerability import Vulnerability, Anomaly, _
from wapitiCore.net.xss_utils import generate_payloads, valid_xss_content_type, find_non_exec_parent, has_csp


class mod_xss(Attack):
    """This class implements a cross site scripting attack"""

    # simple payloads that doesn't rely on their position in the DOM structure
    # payloads injected after closing a tag attribute value (attrval) or in the
    # content of a tag (text node like between <p> and </p>)
    # only trick here must be on character encoding, filter bypassing, stuff like that
    # form the simplest to the most complex, Wapiti will stop on the first working
    independant_payloads = []
    php_self_payload = "%3Cscript%3Ephpselfxss()%3C/script%3E"
    php_self_check = "<script>phpselfxss()</script>"

    name = "xss"

    # two dict exported for permanent XSS scanning
    # GET_XSS structure :
    # {uniq_code : http://url/?param1=value1&param2=uniq_code&param3..., next_uniq_code : ...}
    # GET_XSS = {}
    # POST XSS structure :
    # {uniq_code: [target_url, {param1: val1, param2: uniq_code, param3:...}, referer_ul], next_uniq_code : [...]...}
    # POST_XSS = {}
    TRIED_XSS = {}
    PHP_SELF = []

    # key = taint code, value = (payload, flags)
    SUCCESSFUL_XSS = {}

    PAYLOADS_FILE = "xssPayloads.ini"

    MSG_VULN = _("XSS vulnerability")

    def __init__(self, crawler, persister, logger, attack_options):
        Attack.__init__(self, crawler, persister, logger, attack_options)
        self.independant_payloads = self.payloads

    @staticmethod
    def random_string():
        """Create a random unique ID that will be used to test injection."""
        # doesn't uppercase letters as BeautifulSoup make some data lowercase
        code = "w" + "".join([random.choice("0123456789abcdefghjijklmnopqrstuvwxyz") for __ in range(0, 9)])
        return code, set()

    def attack(self):
        methods = ""
        if self.do_get:
            methods += "G"
        if self.do_post:
            methods += "PF"

        mutator = Mutator(
            methods=methods,
            payloads=self.random_string,
            qs_inject=self.must_attack_query_string,
            skip=self.options.get("skipped_parameters")
        )

        http_resources = self.persister.get_links(attack_module=self.name) if self.do_get else []
        forms = self.persister.get_forms(attack_module=self.name) if self.do_post else []

        for original_request in chain(http_resources, forms):
            if self.verbose >= 1:
                print("[+] {}".format(original_request))

            for mutated_request, parameter, taint, flags in mutator.mutate(original_request):
                try:
                    # We don't display the mutated request here as the payload is not interesting
                    try:
                        response = self.crawler.send(mutated_request)
                    except ReadTimeout:
                        # We just inserted harmless characters, if we get a timeout here, it's not interesting
                        continue
                    else:
                        # We keep a history of taint values we sent because in case of stored value, the taint code
                        # may be found in another webpage by the permanentxss module.
                        self.TRIED_XSS[taint] = (mutated_request, parameter, flags)

                        # Reminder: valid_xss_content_type is not called before before content is not necessary
                        # reflected here, may be found in another webpage so we have to inject tainted values
                        # even if the Content-Type seems uninteresting.
                        if taint.lower() in response.content.lower() and valid_xss_content_type(mutated_request):
                            # Simple text injection worked in HTML response, let's try with JS code
                            payloads = generate_payloads(response.content, taint, self.independant_payloads)

                            # TODO: check that and make it better
                            if PayloadType.get in flags:
                                method = "G"
                            elif PayloadType.file in flags:
                                method = "F"
                            else:
                                method = "P"

                            self.attempt_exploit(method, payloads, original_request, parameter, taint)
                except KeyboardInterrupt as exception:
                    yield exception

            yield original_request

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

    def attempt_exploit(self, method, payloads, original_request, parameter, taint):
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
                response = self.crawler.send(evil_request)
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
                    request_id=original_request.path_id,
                    category=Anomaly.RES_CONSUMPTION,
                    level=Anomaly.MEDIUM_LEVEL,
                    request=evil_request,
                    info=anom_msg,
                    parameter=xss_param
                )
                timeouted = True

            else:
                if (
                        response.status not in (301, 302, 303) and
                        valid_xss_content_type(evil_request) and
                        self.check_payload(response, xss_flags, taint)
                ):
                    self.SUCCESSFUL_XSS[taint] = (xss_payload, xss_flags)
                    message = _("XSS vulnerability found via injection in the parameter {0}").format(xss_param)
                    if has_csp(response):
                        message += ".\n" + _("Warning: Content-Security-Policy is present!")

                    self.add_vuln(
                        request_id=original_request.path_id,
                        category=Vulnerability.XSS,
                        level=Vulnerability.HIGH_LEVEL,
                        request=evil_request,
                        parameter=xss_param,
                        info=message
                    )

                    if xss_param == "QUERY_STRING":
                        injection_msg = Vulnerability.MSG_QS_INJECT
                    else:
                        injection_msg = Vulnerability.MSG_PARAM_INJECT

                    self.log_red("---")
                    self.log_red(
                        injection_msg,
                        self.MSG_VULN,
                        page,
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
                        request_id=original_request.path_id,
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
