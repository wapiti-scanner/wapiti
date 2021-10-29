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
from http.cookiejar import Cookie
from wapitiCore.attack.attack import Attack
from wapitiCore.net.web import Request
from wapitiCore.language.vulnerability import _
from wapitiCore.definitions.secure_cookie import NAME as COOKIE_SECURE_DISABLED
from wapitiCore.definitions.http_only import NAME as COOKIE_HTTPONLY_DISABLED
from wapitiCore.main.log import log_red, log_blue

INFO_COOKIE_HTTPONLY = _("HttpOnly flag is not set in the cookie : {0}")
INFO_COOKIE_SECURE = _("Secure flag is not set in the cookie : {0}")


class ModuleCookieflags(Attack):
    """Evaluate the security of cookies on the website."""
    name = "cookieflags"
    finished = False

    @staticmethod
    def check_secure_flag(cookie: Cookie):
        return cookie.secure

    @staticmethod
    def check_httponly_flag(cookie: Cookie):
        return cookie.has_nonstandard_attr("HttpOnly") or cookie.has_nonstandard_attr("httponly")

    async def must_attack(self, request: Request):
        if self.finished:
            return False

        if request.method == "POST":
            return False

        return request.url == await self.persister.get_root_url()

    async def attack(self, request: Request):
        self.finished = True
        cookies = self.crawler.session_cookies

        for cookie in cookies.jar:
            log_blue(_("Checking cookie : {}").format(cookie.name))
            if not self.check_httponly_flag(cookie):
                log_red(INFO_COOKIE_HTTPONLY.format(cookie.name))
                await self.add_vuln_low(
                    category=COOKIE_HTTPONLY_DISABLED,
                    request=request,
                    info=INFO_COOKIE_HTTPONLY.format(cookie.name)
                )

            if not self.check_secure_flag(cookie):
                log_red(INFO_COOKIE_SECURE.format(cookie.name))
                await self.add_vuln_low(
                    category=COOKIE_SECURE_DISABLED,
                    request=request,
                    info=INFO_COOKIE_SECURE.format(cookie.name)
                )
