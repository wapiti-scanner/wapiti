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
from httpx import RequestError

from wapitiCore.attack.attack import Attack
from wapitiCore.net.web import Request
from wapitiCore.language.vulnerability import _
from wapitiCore.definitions.http_headers import NAME
from wapitiCore.net.page import Page
from wapitiCore.main.log import log_red, log_blue, log_green

INFO_HSTS = _("Strict-Transport-Security is not set")
INFO_XCONTENT_TYPE = _("X-Content-Type-Options is not set")
INFO_XSS_PROTECTION = _("X-XSS-Protection is not set")
INFO_XFRAME_OPTIONS = _("X-Frame-Options is not set")


class ModuleHttpHeaders(Attack):
    """Evaluate the security of HTTP headers."""
    name = "http_headers"
    check_list_xframe = ['deny', 'sameorigin', 'allow-from']
    check_list_xss = ['1']
    check_list_xcontent = ['nosniff']
    check_list_hsts = ['max-age=']

    headers_to_check = {
        "X-Frame-Options": {
            "list": check_list_xframe, "info": INFO_XFRAME_OPTIONS, "log": _("Checking X-Frame-Options :")
        },
        "X-XSS-Protection": {
            "list": check_list_xss, "info": INFO_XSS_PROTECTION, "log": _("Checking X-XSS-Protection :")
        },
        "X-Content-Type-Options": {
            "list": check_list_xcontent, "info": INFO_XCONTENT_TYPE, "log": _("Checking X-Content-Type-Options :")
        },
        "Strict-Transport-Security": {
            "list": check_list_hsts, "info": INFO_HSTS, "log": _("Checking Strict-Transport-Security :")
        }
    }

    @staticmethod
    def is_set(response: Page, header_name, check_list):
        if header_name not in response.headers:
            return False

        return any(element in response.headers[header_name].lower() for element in check_list)

    async def check_header(self, response, request, header, check_list, info, log):
        log_blue(log)
        if not self.is_set(response, header, check_list):
            log_red(info)
            await self.add_vuln_low(
                category=NAME,
                request=request,
                info=info
            )
        else:
            log_green("OK")

    async def must_attack(self, request: Request):
        if self.finished:
            return False

        if request.method == "POST":
            return False

        return request.url == await self.persister.get_root_url()

    async def attack(self, request: Request):
        request_to_root = Request(request.url)
        self.finished = True

        try:
            response = await self.crawler.async_get(request_to_root, follow_redirects=True)
        except RequestError:
            self.network_errors += 1
            return

        for header, value in self.headers_to_check.items():
            await self.check_header(response, request_to_root, header, value["list"], value["info"], value["log"])
