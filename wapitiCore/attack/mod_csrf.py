#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti.sourceforge.io)
# Copyright (C) 2020-2021 Nicolas Surribas
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
from collections import Counter
import math
from requests.exceptions import ReadTimeout

from wapitiCore.attack.attack import Attack
from wapitiCore.language.vulnerability import MEDIUM_LEVEL, Messages, _
from wapitiCore.definitions.csrf import NAME
from wapitiCore.net.web import Request
from wapitiCore.net.crawler import Page


class mod_csrf(Attack):
    """
    Detect forms missing Cross-Site Request Forgery protections (CSRF tokens).
    """

    name = "csrf"

    do_get = False
    do_post = False

    csrf_string = None

    MIN_ENTROPY = 3
    MIN_LENGTH = 8

    TOKEN_FORM_STRINGS = [
        "authenticity_token", "_token", "csrf_token", "csrfname", "csrftoken", "anticsrf",
        "__requestverificationtoken", "token", "csrf", "_csrf_token", "xsrf_token",
        "_csrf", "csrf-token", "xsrf-token", "_wpnonce"
        ]

    TOKEN_HEADER_STRINGS = [
        "csrf-token", "x-csrf-token", "xsrf-token", "x-xsrf-token", "csrfp-token",
        "anti-csrf-token", "x-csrf-header", "x-xsrf-header", "x-csrf-protection"
    ]

    @staticmethod
    def entropy(string: str):
        # Shannon entropy calculation
        # https://stackoverflow.com/questions/15450192/fastest-way-to-compute-entropy-in-python
        probabilities = [n_x / len(string) for x, n_x in Counter(string).items()]
        e_x = [-p_x * math.log(p_x, 2) for p_x in probabilities]
        return sum(e_x)

    def is_csrf_present(self, original_request: Request):
        """Check whether anti-csrf token is present"""

        # Look for anti-csrf token in form params
        for param in original_request.post_params:
            if param[0].lower() in self.TOKEN_FORM_STRINGS:
                self.csrf_string = param[0]
                return param[1]

        # Look for anti-csrf token in HTTP headers
        if original_request.headers:
            for header in original_request.headers:
                if header.lower() in self.TOKEN_HEADER_STRINGS:
                    self.csrf_string = header
                    return original_request.headers[header]

        return None

    def is_csrf_robust(self, csrf_value):
        """Check whether anti-csrf token is robust enough"""

        # csrf value length is too short
        if len(csrf_value) < self.MIN_LENGTH:
            return False

        # csrf value entropy is too low, i.e. csrf value is too predictive
        if self.entropy(csrf_value) < self.MIN_ENTROPY:
            return False

        return True

    @staticmethod
    def is_same_response(original_response: Page, mutated_response: Page):
        """Check whether mutated_response status and content are identical to those of original_response"""

        if original_response.status != mutated_response.status:
            return False

        if original_response.content != mutated_response.content:  # TODO: Maybe too strict
            return False

        return True

    def is_csrf_verified(self, original_request: Request):
        """Check whether anti-csrf token is verified (backend) after submitting request"""

        # Replace anti-csrf token value from form with "wapiti"
        mutated_post_params = [
            param if param[0] != self.csrf_string else [self.csrf_string, "wapiti"]
            for param in original_request.post_params
        ]

        # Replace anti-csrf token value from headers with "wapiti"
        special_headers = {}
        if original_request.headers and self.csrf_string in original_request.headers:
            special_headers[self.csrf_string] = "wapiti"

        mutated_request = Request(
            path=original_request.path,
            method=original_request.method,
            get_params=original_request.get_params,
            post_params=mutated_post_params,
            file_params=original_request.file_params,
            referer=original_request.referer,
            link_depth=original_request.link_depth
        )

        original_response = self.crawler.send(original_request, follow_redirects=True)

        try:
            mutated_response = self.crawler.send(mutated_request, headers=special_headers, follow_redirects=True)

        except ReadTimeout:

            self.log_orange("---")
            self.log_orange(Messages.MSG_TIMEOUT, original_request.path)
            self.log_orange(Messages.MSG_EVIL_REQUEST)
            self.log_orange(mutated_request.http_repr())
            self.log_orange("---")

            anom_msg = Messages.MSG_PARAM_TIMEOUT.format(self.csrf_string)

            self.add_anom(
                request_id=original_request.path_id,
                category=Messages.RES_CONSUMPTION,
                level=MEDIUM_LEVEL,
                request=mutated_request,
                info=anom_msg,
            )

        else:
            return not self.is_same_response(original_response, mutated_response)

        return True

    def attack(self):
        forms = self.persister.get_forms(attack_module=self.name) if self.do_post else []
        # list to ensure only one occurrence per (vulnerable url/post_keys) tuple
        already_vulnerable = []

        for original_request in forms:
            if (original_request.url, original_request.post_keys) in already_vulnerable:
                yield original_request
                continue

            if self.verbose >= 1:
                print("[+] {}".format(original_request))

            csrf_value = self.is_csrf_present(original_request)

            # check if token is present
            if not csrf_value:
                vuln_message = _("Lack of anti CSRF token")
            elif not self.is_csrf_verified(original_request):
                vuln_message = _("CSRF token '{}' is not properly checked in backend").format(self.csrf_string)
            elif not self.is_csrf_robust(csrf_value):
                vuln_message = _("CSRF token '{}' might be easy to predict").format(self.csrf_string)
            else:
                yield original_request
                continue

            already_vulnerable.append((original_request.url, original_request.post_keys))

            self.log_red("---")
            self.log_red(vuln_message)
            self.log_red(original_request.http_repr())
            self.log_red("---")

            self.add_vuln(
                request_id=original_request.path_id,
                category=NAME,
                level=MEDIUM_LEVEL,
                request=original_request,
                info=vuln_message,
            )

            yield original_request
