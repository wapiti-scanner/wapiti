#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (http://wapiti.sourceforge.io)
# Copyright (C) 2018-2020 Nicolas Surribas
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
from itertools import chain

from wapitiCore.attack.attack import Attack
from wapitiCore.net.web import Request
from requests.exceptions import RequestException


class mod_methods(Attack):
    """
    This class detects interesting HTTP methods
    """

    name = "methods"
    PRIORITY = 6
    KNOWN_METHODS = {"GET", "POST", "OPTIONS", "HEAD", "TRACE"}
    do_get = False
    do_post = False

    def attack(self):
        excluded_path = set()
        http_resources = self.persister.get_links(attack_module=self.name) if self.do_get else []
        forms = self.persister.get_forms(attack_module=self.name) if self.do_post else []

        for original_request in chain(http_resources, forms):
            try:
                page = original_request.path
                if page in excluded_path:
                    continue

                excluded_path.add(page)

                option_request = Request(
                    page,
                    "OPTIONS",
                    referer=original_request.referer,
                    link_depth=original_request.link_depth
                )

                if self.verbose == 2:
                    print("[+] {}".format(option_request))

                try:
                    response = self.crawler.send(option_request)
                except RequestException:
                    continue
                else:
                    if 200 <= response.status < 400:
                        methods = response.headers.get("allow", '').upper().split(',')
                        methods = {method.strip() for method in methods if method.strip()}
                        interesting_methods = sorted(methods - self.KNOWN_METHODS)

                        if interesting_methods:
                            self.log_orange("---")
                            self.log_orange(
                                "Interesting methods allowed on {}: {}".format(
                                    page,
                                    ", ".join(interesting_methods)
                                )
                            )
                            self.log_orange("---")
            except (KeyboardInterrupt, RequestException) as exception:
                yield exception

            yield original_request
