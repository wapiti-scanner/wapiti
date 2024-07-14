#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2023-2024 Cyberwatch
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
import uuid

from typing import Optional
from httpx import RequestError
from wapitiCore.attack.attack import Attack
from wapitiCore.definitions.spring4shell import Spring4ShellFinding
from wapitiCore.main.log import log_red, logging
from wapitiCore.net import Request, Response


class ModuleSpring4Shell(Attack):
    """
    Detect the Spring4Shell vulnerability
    """
    name = "spring4shell"

    async def _default_request(self, request_url: str, method: str) -> int:
        request = Request(
            path=request_url,
            method=method,
        )
        response = await self.crawler.async_send(request, follow_redirects=False)
        return response.status

    async def _attack_spring4shell_url(self, request: Request):
        payload_unique_id = uuid.uuid4()
        payload = self._generate_payload(payload_unique_id)

        try:
            if not await self._check_spring4shell("GET", request, payload):
                await self._check_spring4shell("POST", request, payload)

        except RequestError:
            self.network_errors += 1
            return

    async def attack(self, request: Request, response: Optional[Response] = None):
        await self._attack_spring4shell_url(request)

    async def _check_spring4shell(self, method: str, request: Request, payload: str) -> bool:
        key_payload, value_payload = payload.split("=")

        params = request.get_params
        params.append([key_payload, value_payload])

        malicious_request = Request(
            path=request.url,
            method=method,
            get_params=params if method == "GET" else request.get_params,
            post_params=params if method == "POST" else None,
        )

        logging.info(malicious_request)
        try:
            default_response = await self._default_request(request.url, method)
            response = await self.crawler.async_send(malicious_request, follow_redirects=False)
        except RequestError:
            self.network_errors += 1
            return False
        if response.is_redirect:
            return False
        if not response.is_success and default_response != response.status:
            await self._vulnerable(malicious_request)
            return True
        return False

    async def _vulnerable(self, request: Request):
        await self.add_critical(
            finding_class=Spring4ShellFinding,
            request=request,
            info=f"URL {request.url} seems vulnerable to Spring4Shell attack",
            parameter="",
        )

        log_red("---")
        log_red("URL {0} seems vulnerable to Spring4Shell attack", request.url)
        log_red(request.http_repr())
        log_red("---")

    @staticmethod
    def _generate_payload(unique_id: uuid.UUID) -> str:
        return f"class.module.classLoader[{unique_id}]={unique_id}"
