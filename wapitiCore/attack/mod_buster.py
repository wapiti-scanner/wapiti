#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
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
from requests.exceptions import Timeout, ConnectionError

from wapitiCore.attack.attack import Attack
from wapitiCore.net import web


class mod_buster(Attack):
    """
    This class implements a file and directory buster"
    """

    PAYLOADS_FILE = "busterPayloads.txt"

    name = "buster"

    do_get = False
    do_post = False

    def __init__(self, crawler, persister, logger, attack_options):
        Attack.__init__(self, crawler, persister, logger, attack_options)
        self.known_dirs = []
        self.known_pages = []
        self.new_resources = []

    def test_directory(self, path: str):
        if self.verbose == 2:
            print("[¨] Testing directory {0}".format(path))

        test_page = web.Request(path + "does_n0t_exist.htm")
        try:
            response = self.crawler.send(test_page)
            if response.status not in [403, 404]:
                # we don't want to deal with this at the moment
                return

            for candidate, flags in self.payloads:
                url = path + candidate
                if url not in self.known_dirs and url not in self.known_pages and url not in self.new_resources:
                    page = web.Request(path + candidate)
                    try:
                        response = self.crawler.send(page)
                        if response.redirection_url:
                            loc = response.redirection_url
                            # if loc in self.known_dirs or loc in self.known_pages:
                            #     continue
                            if response.is_directory_redirection:
                                self.log_red("Found webpage {0}", loc)
                                self.new_resources.append(loc)
                            else:
                                self.log_red("Found webpage {0}", page.path)
                                self.new_resources.append(page.path)
                        elif response.status not in [403, 404]:
                            self.log_red("Found webpage {0}", page.path)
                            self.new_resources.append(page.path)
                    except Timeout:
                        continue
                    except ConnectionError:
                        continue

        except Timeout:
            pass

    def attack(self):
        urls = self.persister.get_links(attack_module=self.name) if self.do_get else []

        # First we make a list of uniq webdirs and webpages without parameters
        for resource in urls:
            path = resource.path
            if path.endswith("/"):
                if path not in self.known_dirs:
                    self.known_dirs.append(path)
            else:
                if path not in self.known_pages:
                    self.known_pages.append(path)

        # Then for each known webdirs we look for unknown webpages inside
        for current_dir in self.known_dirs:
            self.test_directory(current_dir)
            yield

        # Finally, for each discovered webdirs we look for more webpages
        while self.new_resources:
            current_res = self.new_resources.pop(0)
            if current_res.endswith("/"):
                # Mark as known then explore
                self.known_dirs.append(current_res)
                self.test_directory(current_res)
                yield
            else:
                self.known_pages.append(current_res)
