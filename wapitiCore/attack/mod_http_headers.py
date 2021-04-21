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
from wapitiCore.language.vulnerability import LOW_LEVEL, _
from wapitiCore.definitions.http_headers import NAME
from wapitiCore.net.page import Page

INFO_HSTS = _("Strict-Transport-Security is not set")
INFO_XCONTENT_TYPE = _("X-Content-Type-Options is not set")
INFO_XSS_PROTECTION = _("X-XSS-Protection is not set")
INFO_XFRAME_OPTIONS = _("X-Frame-Options is not set")


class mod_http_headers(Attack):
    """Evaluate the security of HTTP headers."""
    name = "http_headers"
    check_list_xframe = ['deny', 'sameorigin', 'allow-from']
    check_list_xss = ['1']
    check_list_xcontent = ['nosniff']
    check_list_hsts = ['max-age=']

    def is_set(self, response: Page, header_name, check_list):
        if header_name not in response.headers:
            return False

        return any(element in response.headers[header_name].lower() for element in check_list)

    def must_attack(self, request: Request):
        if self.finished:
            return False

        if request.method == "POST":
            return False

        return request.url == self.persister.get_root_url()

    async def attack(self, request: Request):
        request_to_root = Request(request.url)
        self.finished = True

        try:
            response = await self.crawler.async_get(request_to_root, follow_redirects=True)
        except RequestError:
            self.network_errors += 1
            return

        self.log_blue(_("Checking X-Frame-Options :"))
        if not self.is_set(response, "X-Frame-Options", self.check_list_xframe):
            self.log_red(INFO_XFRAME_OPTIONS)
            self.add_vuln(
                category=NAME,
                level=LOW_LEVEL,
                request=request_to_root,
                info=INFO_XFRAME_OPTIONS
            )
        else:
            self.log_green("OK")

        self.log_blue(_("Checking X-XSS-Protection :"))
        if not self.is_set(response, "X-XSS-Protection", self.check_list_xss):
            self.log_red(INFO_XSS_PROTECTION)
            self.add_vuln(
                category=NAME,
                level=LOW_LEVEL,
                request=request_to_root,
                info=INFO_XSS_PROTECTION
            )
        else:
            self.log_green("OK")

        self.log_blue(_("Checking X-Content-Type-Options :"))
        if not self.is_set(response, "X-Content-Type-Options", self.check_list_xcontent):
            self.log_red(INFO_XCONTENT_TYPE)
            self.add_vuln(
                category=NAME,
                level=LOW_LEVEL,
                request=request_to_root,
                info=INFO_XCONTENT_TYPE
            )
        else:
            self.log_green("OK")

        self.log_blue(_("Checking Strict-Transport-Security :"))
        if not self.is_set(response, "Strict-Transport-Security", self.check_list_hsts):
            self.log_red(INFO_HSTS)
            self.add_vuln(
                category=NAME,
                level=LOW_LEVEL,
                request=request_to_root,
                info=INFO_HSTS
            )
        else:
            self.log_green("OK")
