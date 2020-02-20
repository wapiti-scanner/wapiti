#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (http://wapiti.sourceforge.io)
# Copyright (C) 2008-2020 Nicolas Surribas
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
from urllib.parse import quote

from requests.exceptions import ReadTimeout, HTTPError, RequestException

from wapitiCore.attack.attack import Attack
from wapitiCore.language.vulnerability import Vulnerability, Anomaly, _


class mod_crlf(Attack):
    """This class implements a CRLF attack"""
    # Won't work with PHP >= 4.4.2

    name = "crlf"
    MSG_VULN = _("CRLF Injection")
    do_get = False
    do_post = False
    payloads = (quote("http://www.google.fr\r\nwapiti: 3.0.3 version"), set())

    def attack(self):
        mutator = self.get_mutator()

        http_resources = self.persister.get_links(attack_module=self.name) if self.do_get else []

        for http_res in http_resources:
            page = http_res.path

            for mutated_request, parameter, payload, flags in mutator.mutate(http_res):
                try:
                    if self.verbose == 2:
                        print("+ {0}".format(mutated_request.url))
                    try:
                        response = self.crawler.send(mutated_request)

                    except ReadTimeout:
                        self.add_anom(
                            request_id=http_res.path_id,
                            category=Anomaly.RES_CONSUMPTION,
                            level=Anomaly.MEDIUM_LEVEL,
                            request=mutated_request,
                            parameter=parameter,
                            info="Timeout (" + parameter + ")"
                        )

                        self.log_orange("---")
                        self.log_orange(Anomaly.MSG_TIMEOUT, page)
                        self.log_orange(Anomaly.MSG_EVIL_REQUEST)
                        self.log_orange(mutated_request.http_repr())
                        self.log_orange("---")

                    except HTTPError:
                        self.log(_("Error: The server did not understand this request"))
                    else:
                        if "wapiti" in response.headers:
                            self.add_vuln(
                                request_id=http_res.path_id,
                                category=Vulnerability.CRLF,
                                level=Vulnerability.HIGH_LEVEL,
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
