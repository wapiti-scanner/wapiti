#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2018-2023 Nicolas Surribas
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
from typing import Optional, Set, Dict

from httpx import RequestError

from wapitiCore.main.log import log_verbose, log_orange

from wapitiCore.attack.attack import Attack
from wapitiCore.definitions.methods import MethodsFinding
from wapitiCore.net import Request, Response


def get_allowed_methods(response: Response) -> Set[str]:
    methods = response.headers.get("allow", "").upper().split(",")
    return {method.strip() for method in methods if method.strip()}


def format_statuses(statuses: Dict[str, int]) -> str:
    return " ".join([f"{method} ({statuses[method]})" for method in sorted(statuses)])


def is_interesting(method: str, response: Response) -> bool:
    # This is basic config like default Nginx or CloudFlare protected websites
    if response.status in (403, 405):
        return False

    # If the method is HEAD and its body is empty, this behavior is not abnormal
    if method == "HEAD" and not response.content:
        return False

    if method == "CONNECT" and response.status == 400:
        # Common as CONNECT should be used with a resource
        return False

    if response.status == 403 and (
        "This distribution is not configured to allow the HTTP request method that was used for this request"
    ) in response.content:
        return False

    if method == "TRACE" and "TRACE /" not in response.content:
        return False

    return True


class ModuleMethods(Attack):
    """
    Detect uncommon HTTP methods (like PUT) that may be allowed by a script.
    """

    name = "methods"
    PRIORITY = 6
    KNOWN_METHODS = {"GET", "POST", "OPTIONS", "HEAD", "TRACE"}
    UNCOMMON_METHODS = {"CONNECT", "DELETE", "PUT", "PATCH"}
    do_get = True
    do_post = True
    excluded_path = set()
    hosts_with_trace = set()

    async def query_method(self, path: str, method: str) -> Response:
        request = Request(
            path,
            method,
        )
        log_verbose(f"[¨] {request}")
        return await self.crawler.async_send(request)

    async def must_attack(self, request: Request, response: Optional[Response] = None):

        if response.is_directory_redirection:
            return False
        return request.path not in self.excluded_path

    async def attack(self, request: Request, response: Optional[Response] = None):
        # We first try to obtain the list of allowed methods using OPTIONS
        # then we test each of those and we compare the status code and content to the response
        # given to a GET request (that will be sent in every case).
        # If OPTIONS isn't implemented we send a request for each HTTP method from a hardcoded list
        # To filter most common cases we call the function called `is_interesting` above.
        # The behavior of this module is a bit different from https://svn.nmap.org/nmap/scripts/http-methods.nse
        page = request.path
        self.excluded_path.add(page)
        methods_to_test = self.KNOWN_METHODS | self.UNCOMMON_METHODS
        options_succeed = False
        statuses = {}

        try:
            options_response = await self.query_method(page, "OPTIONS")
        except RequestError:
            self.network_errors += 1
        else:
            allowed_methods = get_allowed_methods(options_response)
            if allowed_methods:
                methods_to_test = allowed_methods
                log_orange(f"Methods found in the header: {','.join(methods_to_test)}")
                options_succeed = True
                statuses["OPTIONS"] = options_response.status

        try:
            get_response = await self.query_method(page, "GET")
        except RequestError:
            self.network_errors += 1
            # We leave because GET serves as reference
            return

        methods_to_test -= {"GET", "OPTIONS"}

        for method in methods_to_test:
            if method == "GET":
                continue

            try:
                method_response = await self.query_method(page, method)
            except RequestError:
                self.network_errors += 1
                continue

            if not is_interesting(method, method_response):
                continue

            if method == "TRACE" and request.netloc not in self.hosts_with_trace:
                # Log this only once per netloc
                self.hosts_with_trace.add(request.netloc)
                log_orange("[!] TRACE method is allowed on the server")
                await self.add_info(
                    finding_class=MethodsFinding,
                    request=request,
                    info="HTTP TRACE method is allowed on the webserver",
                )

            status_different = method_response.status != get_response.status
            content_different = method_response.content != get_response.content
            if not status_different and not content_different:
                continue

            statuses[method] = method_response.status
            logging_string = f"Method {method} returned "
            differences_str = []
            if status_different:
                differences_str.append(f"{method_response.status} server code")
            if content_different:
                differences_str.append("a body content")

            logging_string += f"{' and '.join(differences_str)} different from GET method on {page}"
            log_orange(logging_string)

        message = (
            f"Possible interesting methods (using {'OPTIONS' if options_succeed else 'heuristics'}) "
            f"on {page}: {format_statuses(statuses)}"
        )

        await self.add_info(
            finding_class=MethodsFinding,
            request=request,
            info=message,
        )
