#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti.sourceforge.io)
# Copyright (C) 2019-2021 Nicolas Surribas
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

from wapitiCore.attack.attack import Attack, Flags
from wapitiCore.language.vulnerability import Messages, LOW_LEVEL, _
from wapitiCore.definitions.redirect import NAME


class mod_redirect(Attack):
    """Detect Open Redirect vulnerabilities."""
    # Won't work with PHP >= 4.4.2

    name = "redirect"
    MSG_VULN = _("Open Redirect")
    do_get = True
    do_post = False
    payloads = ("https://openbugbounty.org/", Flags())

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
                            category=NAME,
                            level=LOW_LEVEL,
                            request=mutated_request,
                            parameter=parameter,
                            info=_("{0} via injection in the parameter {1}").format(self.MSG_VULN, parameter)
                        )

                        if parameter == "QUERY_STRING":
                            injection_msg = Messages.MSG_QS_INJECT
                        else:
                            injection_msg = Messages.MSG_PARAM_INJECT

                        self.log_red("---")
                        self.log_red(
                            injection_msg,
                            self.MSG_VULN,
                            page,
                            parameter
                        )
                        self.log_red(Messages.MSG_EVIL_REQUEST)
                        self.log_red(mutated_request.http_repr())
                        self.log_red("---")

                except (RequestException, KeyboardInterrupt) as exception:
                    yield exception

            yield http_res
