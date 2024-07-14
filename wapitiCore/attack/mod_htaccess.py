#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2009-2023 Nicolas Surribas
# Copyright (C) 2021-2024 Cyberwatch
#
# Original authors :
# Anthony DUBOCAGE
# Guillaume TRANCHANT
# Gregory FONTAINE
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

from wapitiCore.attack.attack import Attack
from wapitiCore.definitions.htaccess import HtaccessBypassFinding
from wapitiCore.net import Request, Response
from wapitiCore.main.log import log_red, log_verbose


class ModuleHtaccess(Attack):
    """
    Attempt to bypass access controls to a resource by using a custom HTTP method.
    """

    name = "htaccess"

    do_get = True
    do_post = True

    async def must_attack(self, request: Request, response: Optional[Response] = None):
        if request.path in self.attacked_get:
            return False

        if response.is_directory_redirection:
            return False

        return response.status in (401, 402, 403, 407)

    async def attack(self, request: Request, response: Optional[Response] = None):
        url = request.path
        referer = request.referer
        original_status = response.status
        headers = {}
        if referer:
            headers["referer"] = referer

        evil_req = Request(url, method="ABC")
        try:
            response = await self.crawler.async_send(evil_req, headers=headers)
        except RequestError:
            self.network_errors += 1
            return

        if response.status == 404 or response.status < 400 or response.status >= 500:
            # Every 4xx status should be uninteresting (specially bad request in our case)

            unblocked_content = response.content

            log_red("---")
            await self.add_medium(
                request_id=request.path_id,
                finding_class=HtaccessBypassFinding,
                request=evil_req,
                info=f"{evil_req.url} bypassable weak restriction",
                response=response
            )
            log_red(f"Weak restriction bypass vulnerability: {evil_req.url}")
            log_red(f"HTTP status code changed from {original_status} to {response.status}")

            log_verbose("Source code:")
            log_verbose(unblocked_content)
            log_red("---")

        self.attacked_get.append(url)
