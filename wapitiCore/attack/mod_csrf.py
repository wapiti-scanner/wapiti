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
from httpx import RequestError

from wapitiCore.attack.attack import Attack
from wapitiCore.language.vulnerability import MEDIUM_LEVEL, _
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

    def __init__(self, crawler, persister, logger, attack_options, stop_event):
        Attack.__init__(self, crawler, persister, logger, attack_options, stop_event)
        # list to ensure only one occurrence per (vulnerable url/post_keys) tuple
        self.already_vulnerable = []

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

    async def is_csrf_verified(self, original_request: Request):
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

        try:
            original_response = await self.crawler.async_send(original_request, follow_redirects=True)
        except RequestError:
            # We can't compare so act like it is secure
            self.network_errors += 1
            return True

        try:
            mutated_response = await self.crawler.async_send(
                mutated_request,
                headers=special_headers,
                follow_redirects=True
            )
        except RequestError:
            # Do not log anything: the payload is not harmful enough for such behavior
            self.network_errors += 1
        else:
            return not self.is_same_response(original_response, mutated_response)

        return True

    def must_attack(self, request: Request):
        if request.method != "POST":
            return False

        if (request.url, request.post_keys) in self.already_vulnerable:
            return False

        return True

    async def attack(self, request: Request):
        csrf_value = self.is_csrf_present(request)

        # check if token is present
        if not csrf_value:
            vuln_message = _("Lack of anti CSRF token")
        elif not await self.is_csrf_verified(request):
            vuln_message = _("CSRF token '{}' is not properly checked in backend").format(self.csrf_string)
        elif not self.is_csrf_robust(csrf_value):
            vuln_message = _("CSRF token '{}' might be easy to predict").format(self.csrf_string)
        else:
            return

        self.already_vulnerable.append((request.url, request.post_keys))

        self.log_red("---")
        self.log_red(vuln_message)
        self.log_red(request.http_repr())
        self.log_red("---")

        self.add_vuln(
            request_id=request.path_id,
            category=NAME,
            level=MEDIUM_LEVEL,
            request=request,
            info=vuln_message,
        )
