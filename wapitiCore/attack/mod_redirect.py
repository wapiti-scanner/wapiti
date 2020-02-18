#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (http://wapiti.sourceforge.io)
# Copyright (C) 2019-2020 Nicolas Surribas
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


class mod_redirect(Attack):
    """This class implements an open-redirect attack"""
    # Won't work with PHP >= 4.4.2

    name = "redirect"
    MSG_VULN = _("Open Redirect")
    do_get = True
    do_post = False
    payloads = ("https://openbugbounty.org/", set())

    def attack(self):
        mutator = self.get_mutator()

        http_resources = self.persister.get_links(attack_module=self.name) if self.do_get else []

        for http_res in http_resources:
            page = http_res.path

            for mutated_request, parameter, payload, flags in mutator.mutate(http_res):
                try:
                    if self.verbose == 2:
                        print("+ {0}".format(mutated_request.url))

                    response = self.crawler.send(mutated_request)

                    if any([url.startswith("https://openbugbounty.org/") for url in response.all_redirections]):
                        self.add_vuln(
                            request_id=http_res.path_id,
                            category=Vulnerability.REDIRECT,
                            level=Vulnerability.MEDIUM_LEVEL,
                            request=mutated_request,
                            parameter=parameter,
                            info=_("{0} via injection in the parameter {1}").format(self.MSG_VULN, parameter)
                        )

                        if parameter == "QUERY_STRING":
                            injection_msg = Vulnerability.MSG_QS_INJECT
                        else:
                            injection_msg = Vulnerability.MSG_PARAM_INJECT

                        self.log_red("---")
                        self.log_red(
                            injection_msg,
                            self.MSG_VULN,
                            page,
                            parameter
                        )
                        self.log_red(Vulnerability.MSG_EVIL_REQUEST)
                        self.log_red(mutated_request.http_repr())
                        self.log_red("---")

                except (RequestException, KeyboardInterrupt) as exception:
                    yield exception

            yield http_res
