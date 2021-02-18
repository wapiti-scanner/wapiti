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
from wapitiCore.attack.attack import Attack
from wapitiCore.net.web import Request
from wapitiCore.language.vulnerability import _, LOW_LEVEL
from wapitiCore.definitions.secure_cookie import NAME as COOKIE_SECURE_DISABLED
from wapitiCore.definitions.http_only import NAME as COOKIE_HTTPONLY_DISABLED

INFO_COOKIE_HTTPONLY = _("HttpOnly flag is not set in the cookie : {0}")
INFO_COOKIE_SECURE = _("Secure flag is not set in the cookie : {0}")


class mod_cookieflags(Attack):
    """Evaluate the security of cookies on the website."""
    name = "cookieflags"

    @staticmethod
    def check_secure_flag(cookie: object):
        return cookie.secure

    @staticmethod
    def check_httponly_flag(cookie: object):
        return "HttpOnly" in cookie._rest

    def attack(self):
        url = self.persister.get_root_url()
        request = Request(url)
        cookies = self.crawler.session_cookies
        for cookie in cookies:
            self.log_blue(_("Checking cookie : {}").format(cookie.name))
            if not self.check_httponly_flag(cookie):
                self.log_red(INFO_COOKIE_HTTPONLY.format(cookie.name))
                self.add_vuln(
                    category=COOKIE_HTTPONLY_DISABLED,
                    level=LOW_LEVEL,
                    request=request,
                    info=INFO_COOKIE_HTTPONLY.format(cookie.name)
                )

            if not self.check_secure_flag(cookie):
                self.log_red(INFO_COOKIE_SECURE.format(cookie.name))
                self.add_vuln(
                    category=COOKIE_SECURE_DISABLED,
                    level=LOW_LEVEL,
                    request=request,
                    info=INFO_COOKIE_SECURE.format(cookie.name)
                )

        yield
