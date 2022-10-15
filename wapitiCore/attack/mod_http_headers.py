# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2020-2022 Nicolas Surribas
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
from typing import List, Optional

from httpx import RequestError
from wapitiCore.attack.attack import Attack
from wapitiCore.definitions.http_headers import (
    NAME, WSTG_CODE_CONTENT_TYPE_OPTIONS, WSTG_CODE_FRAME_OPTIONS,
    WSTG_CODE_STRICT_TRANSPORT_SECURITY)
from wapitiCore.main.log import log_blue, log_green, log_red
from wapitiCore.net.response import Response
from wapitiCore.net import Request

INFO_HSTS = "Strict-Transport-Security is not set"
INFO_XCONTENT_TYPE = "X-Content-Type-Options is not set"
INFO_XFRAME_OPTIONS = "X-Frame-Options is not set"


class ModuleHttpHeaders(Attack):
    """Evaluate the security of HTTP headers."""
    name = "http_headers"
    check_list_xframe = ['deny', 'sameorigin', 'allow-from']
    check_list_xcontent = ['nosniff']
    check_list_hsts = ['max-age=']

    headers_to_check = {
        "X-Frame-Options": {
            "list": check_list_xframe,
            "info": INFO_XFRAME_OPTIONS,
            "log": "Checking X-Frame-Options :",
            "wstg": WSTG_CODE_FRAME_OPTIONS
        },
        "X-Content-Type-Options": {
            "list": check_list_xcontent,
            "info": INFO_XCONTENT_TYPE,
            "log": "Checking X-Content-Type-Options :",
            "wstg": WSTG_CODE_CONTENT_TYPE_OPTIONS
        },
        "Strict-Transport-Security": {
            "list": check_list_hsts,
            "info": INFO_HSTS,
            "log": "Checking Strict-Transport-Security :",
            "wstg": WSTG_CODE_STRICT_TRANSPORT_SECURITY
        }
    }

    @staticmethod
    def is_set(response: Response, header_name, check_list):
        if header_name not in response.headers:
            return False

        return any(element in response.headers[header_name].lower() for element in check_list)

    async def check_header(
        self,
        response: Response,
        request: Request,
        header: str,
        check_list: List[str],
        info: str,
        log: str,
        wstg: str
    ):
        log_blue(log)
        if not self.is_set(response, header, check_list):
            log_red(info)
            await self.add_vuln_low(
                category=NAME,
                request=request,
                info=info,
                wstg=wstg,
                response=response
            )
        else:
            log_green("OK")

    async def must_attack(self, request: Request, response: Optional[Response] = None):
        if request.method == "POST":
            return False

        if request.is_root and not request.parameters_count:
            return True

        if request.url == await self.persister.get_root_url():
            return True

        return False

    async def attack(self, request: Request, response: Optional[Response] = None):
        request_to_root = Request(request.url, "GET")
        self.finished = True

        try:
            response = await self.crawler.async_send(request_to_root)
        except RequestError:
            self.network_errors += 1
            return

        for header, value in self.headers_to_check.items():
            if header == "Strict-Transport-Security" and request_to_root.scheme != "https":
                continue

            await self.check_header(
                response,
                request_to_root,
                header,
                value["list"],
                value["info"],
                value["log"],
                value["wstg"]
            )
