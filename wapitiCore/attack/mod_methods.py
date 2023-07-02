#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2018-2023 Nicolas Surribas
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
from typing import Optional

from httpx import RequestError

from wapitiCore.main.log import log_verbose, log_orange

from wapitiCore.attack.attack import Attack
from wapitiCore.definitions.methods import NAME, WSTG_CODE
from wapitiCore.net import Request, Response


class ModuleMethods(Attack):
    """
    Detect uncommon HTTP methods (like PUT) that may be allowed by a script.
    """

    name = "methods"
    PRIORITY = 6
    KNOWN_METHODS = {"GET", "POST", "OPTIONS", "HEAD", "TRACE", }
    UNCOMMON_METHODS = {"CONNECT", "DELETE", "PUT", "PATCH"}
    do_get = True
    do_post = True
    excluded_path = set()

    async def discover_methods(self, request: Request, response: Response, methods: set):
        """
        A function to try the various methods returned by an OPTIONS method and comparing them
        with the method used by the crawler to see the differences.
        If OPTIONS returned nothing (empty methods) or a 404 status code,
        it will blindly try all the known methods. A fully empty OPTIONS
        methods seems suspicious so it's better to ultimately check everything.

        Parameter List
        -------------
        request : Request
            Request made previously, useful for its informations in order to make new requests
        response : Response
            Response from the request argument, used to compare to responses from requests made with methods
        methods: set
            set of all methods returned by an OPTIONS method request

        Return object
        -------------
        methods_dict : dict
            dictionnary referencing relevant methods (not 405 status code, differences with the response in argument)
            and their informations

        """
        methods_dict = {}
        # Testing and comparing the uncommon methods,
        # not_allowed_methods record all the methods
        # returning a 405 error which will be removed
        all_but_options_method = set.union(self.KNOWN_METHODS, self.UNCOMMON_METHODS)-{'OPTIONS'}
        for method in (methods-self.KNOWN_METHODS if methods else all_but_options_method):
            uncommon_request = Request(
                request.path,
                method,
                referer=request.referer,
                link_depth=request.link_depth
            )
            try:
                log_verbose(f"[+] {uncommon_request}")
                uncommon_response = await self.crawler.async_send(uncommon_request)
            except RequestError:
                self.network_errors += 1
                return
            if uncommon_response.status != 405:
                # If the method is HEAD and its body is empty, this behavior is not abnormal
                methods_dict.update({method: {"code": uncommon_response.status,
                                              "status_different": response.status != uncommon_response.status,
                                              "content_different": False
                                              if (method == 'HEAD' and uncommon_response.content == "")
                                              else response.content != uncommon_response.content,
                                              "response": uncommon_response,
                                              "request": uncommon_request
                                              }})

        return methods_dict

    async def must_attack(self, request: Request, response: Optional[Response] = None):
        return request.path not in self.excluded_path

    async def attack(self, request: Request, response: Optional[Response] = None):
        page = request.path
        self.excluded_path.add(page)

        option_request = Request(
            page,
            "OPTIONS",
            referer=request.referer,
            link_depth=request.link_depth
        )

        log_verbose(f"[+] {option_request}")

        try:
            option_response = await self.crawler.async_send(option_request)
        except RequestError:
            self.network_errors += 1
            return

        # If options response status code is 2** or 301/2/3/5/7
        option_exist = (option_response.is_success or option_response.is_redirect)
        if option_exist:
            methods = option_response.headers.get("allow", '').upper().split(',')
            methods = {method.strip() for method in methods if method.strip()}
            log_orange(f"Methods found in the header: {','.join(methods)}")
        else:
            # Giving an empty method set to the discover method will
            # make it try all the methods blindly
            log_orange("No methods found in the header, blindly try all the methods")
            methods = {}
        interesting_methods = await self.discover_methods(request, response, methods)

        if not interesting_methods:
            log_orange("No interesting method found")
            return

        log_orange(interesting_methods)
        log_orange("---")
        # methods returned by the OPTIONS method request
        option_log = f"Interesting methods allowed on {page}: {', '.join(list(interesting_methods.keys()))}"
        if option_exist:
            log_orange(option_log)
            await self.add_addition(
                category=NAME,
                request=option_request,
                info=option_log,
                wstg=WSTG_CODE,
                response=option_response
            )
        # if a method has relevant information, it will be listed
        for method, data in interesting_methods.items():
            if not (data['status_different'] or data['content_different']):
                continue
            logging_string = f"Method {method} returned "
            differences_str = []
            if data['status_different']:
                differences_str.append(f"{data['code']} server code")
            if data['content_different']:
                differences_str.append("a body content")
            logging_string += f"{' and '.join(differences_str)} different from GET method on {page}"
            log_orange(logging_string)
            await self.add_addition(
                category=NAME,
                request=data['request'],
                info=logging_string,
                wstg=WSTG_CODE,
                response=data['response']
            )
        if option_exist or interesting_methods:
            log_orange("---")
