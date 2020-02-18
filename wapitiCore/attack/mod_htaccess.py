#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (http://wapiti.sourceforge.io)
# Copyright (C) 2009-2020 Nicolas Surribas
#
# Original authors :
# Anthony DUBOCAGE
# Guillaume TRANCHANT
# Gregory FONTAINE
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
from requests.exceptions import RequestException

from wapitiCore.attack.attack import Attack
from wapitiCore.language.vulnerability import Vulnerability, _
from wapitiCore.net import web


class mod_htaccess(Attack):
    """
    This class implements a htaccess attack
    """

    name = "htaccess"

    do_get = False
    do_post = False

    def attack(self):
        http_resources = self.persister.get_links(attack_module=self.name) if self.do_get else []

        for original_request in http_resources:
            url = original_request.path
            referer = original_request.referer
            headers = {}
            if referer:
                headers["referer"] = referer

            if url not in self.attacked_get:
                if original_request.status in (401, 402, 403, 407):
                    # The ressource is forbidden
                    try:
                        evil_req = web.Request(url, method="ABC")
                        response = self.crawler.send(evil_req, headers=headers)
                        unblocked_content = response.content

                        if response.status == 404 or response.status < 400 or response.status >= 500:
                            # Every 4xx status should be uninteresting (specially bad request in our case)

                            self.log_red("---")
                            self.add_vuln(
                                request_id=original_request.path_id,
                                category=Vulnerability.HTACCESS,
                                level=Vulnerability.HIGH_LEVEL,
                                request=evil_req,
                                info=_("{0} bypassable weak restriction").format(evil_req.url)
                            )
                            self.log_red(_("Weak restriction bypass vulnerability: {0}"), evil_req.url)
                            self.log_red(_("HTTP status code changed from {0} to {1}").format(
                                original_request.status,
                                response.status
                            ))

                            if self.verbose == 2:
                                self.log_red(_("Source code:"))
                                self.log_red(unblocked_content)
                            self.log_red("---")

                        self.attacked_get.append(url)
                    except (RequestException, KeyboardInterrupt) as exception:
                        yield exception

            yield original_request
