# This file is part of the Wapiti project (http://wapiti.sourceforge.io)
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
from wapitiCore.language.vulnerability import Additional, _


class mod_cookieflags(Attack):
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
                self.log_red(Additional.INFO_COOKIE_HTTPONLY.format(cookie.name))
                self.add_addition(
                    category=Additional.COOKIE_HTTPONLY_DISABLED,
                    level=Additional.LOW_LEVEL,
                    request=request,
                    info=Additional.INFO_COOKIE_HTTPONLY.format(cookie.name)
                )

            if not self.check_secure_flag(cookie):
                self.log_red(Additional.INFO_COOKIE_SECURE.format(cookie.name))
                self.add_addition(
                    category=Additional.COOKIE_SECURE_DISABLED,
                    level=Additional.LOW_LEVEL,
                    request=request,
                    info=Additional.INFO_COOKIE_SECURE.format(cookie.name)
                )

        yield
