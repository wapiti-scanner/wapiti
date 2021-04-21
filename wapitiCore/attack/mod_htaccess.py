#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti.sourceforge.io)
# Copyright (C) 2009-2021 Nicolas Surribas
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
from httpx import RequestError

from wapitiCore.attack.attack import Attack
from wapitiCore.language.vulnerability import MEDIUM_LEVEL, _
from wapitiCore.definitions.htaccess import NAME
from wapitiCore.net.web import Request


class mod_htaccess(Attack):
    """
    Attempt to bypass access controls to a resource by using a custom HTTP method.
    """

    name = "htaccess"

    do_get = False
    do_post = False

    def must_attack(self, request: Request):
        if request.path in self.attacked_get:
            return False

        return request.status in (401, 402, 403, 407)

    async def attack(self, request: Request):
        url = request.path
        referer = request.referer
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

            self.log_red("---")
            self.add_vuln(
                request_id=request.path_id,
                category=NAME,
                level=MEDIUM_LEVEL,
                request=evil_req,
                info=_("{0} bypassable weak restriction").format(evil_req.url)
            )
            self.log_red(_("Weak restriction bypass vulnerability: {0}"), evil_req.url)
            self.log_red(_("HTTP status code changed from {0} to {1}").format(
                request.status,
                response.status
            ))

            if self.verbose == 2:
                self.log_red(_("Source code:"))
                self.log_red(unblocked_content)
            self.log_red("---")

        self.attacked_get.append(url)
