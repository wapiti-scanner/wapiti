# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2020-2023 Nicolas Surribas
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
from typing import List, Optional, Type

from httpx import RequestError
from wapitiCore.attack.attack import Attack
from wapitiCore.definitions import FindingBase
from wapitiCore.definitions.http_headers import ClickjackingFinding, MimeTypeConfusionFinding, HstsFinding
from wapitiCore.main.log import log_blue, log_green, log_orange, log_red
from wapitiCore.net.response import Response
from wapitiCore.net import Request

HSTS_NOT_SET = "Strict-Transport-Security is not set"
XCONTENT_TYPE_NOT_SET = "X-Content-Type-Options is not set"
XFRAME_OPTIONS_NOT_SET = "X-Frame-Options is not set"
INVALID_HSTS = "Strict-Transport-Security has an invalid value"
INVALID_XCONTENT_TYPE = "X-Content-Type-Options has an invalid value"
INVALID_XFRAME_OPTIONS = "X-Frame-Options has an invalid value"


class ModuleHttpHeaders(Attack):
    """Evaluate the security of HTTP headers."""
    name = "http_headers"
    check_list_xframe = ['deny', 'sameorigin']
    check_list_xcontent = ['nosniff']
    check_list_hsts = ['max-age=']

    headers_to_check = {
        "X-Frame-Options": {
            "list": check_list_xframe,
            "info": {"error": XFRAME_OPTIONS_NOT_SET, "warning": INVALID_XFRAME_OPTIONS},
            "log": "Checking X-Frame-Options:",
            "finding": ClickjackingFinding,
        },
        "X-Content-Type-Options": {
            "list": check_list_xcontent,
            "info": {"error": XCONTENT_TYPE_NOT_SET, "warning": INVALID_XCONTENT_TYPE},
            "log": "Checking X-Content-Type-Options:",
            "finding": MimeTypeConfusionFinding,
        },
        "Strict-Transport-Security": {
            "list": check_list_hsts,
            "info": {"error": HSTS_NOT_SET, "warning": INVALID_HSTS},
            "log": "Checking Strict-Transport-Security:",
            "finding": HstsFinding,
        }
    }

    @staticmethod
    def is_set(response: Response, header_name):
        if header_name not in response.headers:
            return False
        return True

    @staticmethod
    def contains(response: Response, header_name, check_list):
        return any(element in response.headers[header_name].lower() for element in check_list)

    async def check_header(
        self,
        response: Response,
        request: Request,
        header: str,
        check_list: List[str],
        info: dict[str, str],
        log: str,
        finding: Type[FindingBase],
    ):
        log_blue(log)
        if not self.is_set(response, header):
            log_red(info["error"])
            await self.add_low(
                finding_class=finding,
                request=request,
                info=info["error"],
                response=response
            )
        elif not self.contains(response, header, check_list):
            log_orange(info["warning"])
            await self.add_low(
                finding_class=finding,
                request=request,
                info=info["warning"],
                response=response
            )
        else:
            log_green("OK")

    async def must_attack(self, request: Request, response: Optional[Response] = None):
        if request.method == "POST":
            return False

        if response.is_directory_redirection:
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
                value["finding"],
            )
