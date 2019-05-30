#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (http://wapiti.sourceforge.net)
# Copyright (C) 2008-2018 Nicolas Surribas
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
from wapitiCore.language.vulnerability import Vulnerability, Anomaly, _
from requests.exceptions import ReadTimeout, RequestException


class mod_blindsql(Attack):
    """
    This class implements an SQL Injection attack
    """

    PAYLOADS_FILE = "blindSQLPayloads.txt"
    blind_sql_payloads = []
    TIME_TO_SLEEP = 6
    name = "blindsql"
    require = ["sql"]
    PRIORITY = 6

    MSG_VULN = _("Blind SQL vulnerability")

    def __init__(self, crawler, persister, logger, attack_options):
        Attack.__init__(self, crawler, persister, logger, attack_options)
        self.blind_sql_payloads = self.payloads
        self.excluded_get = []
        self.excluded_post = []

    def set_timeout(self, timeout):
        self.TIME_TO_SLEEP = str(1 + int(timeout))

    def attack(self):
        mutator = self.get_mutator()

        http_resources = self.persister.get_links(attack_module=self.name) if self.do_get else []
        forms = self.persister.get_forms(attack_module=self.name) if self.do_post else []

        for original_request in chain(http_resources, forms):
            page = original_request.path
            saw_internal_error = False

            if self.verbose >= 1:
                print("[+] {}".format(original_request))

            for mutated_request, parameter, payload, flags in mutator.mutate(original_request):
                try:
                    if self.verbose == 2:
                        print("[¨] {0}".format(mutated_request))

                    try:
                        response = self.crawler.send(mutated_request)
                    except ReadTimeout:

                        if parameter == "QUERY_STRING":
                            vuln_message = Vulnerability.MSG_QS_INJECT.format(self.MSG_VULN, page)
                            log_message = Vulnerability.MSG_QS_INJECT
                        else:
                            vuln_message = _("{0} via injection in the parameter {1}").format(self.MSG_VULN, parameter)
                            log_message = Vulnerability.MSG_PARAM_INJECT

                        self.add_vuln(
                            request_id=original_request.path_id,
                            category=Vulnerability.BLIND_SQL_INJECTION,
                            level=Vulnerability.HIGH_LEVEL,
                            request=mutated_request,
                            info=vuln_message,
                            parameter=parameter
                        )

                        self.log_red("---")
                        self.log_red(
                            log_message,
                            self.MSG_VULN,
                            page,
                            parameter
                        )
                        self.log_red(Vulnerability.MSG_EVIL_REQUEST)
                        self.log_red(mutated_request.http_repr())
                        self.log_red("---")

                        # We reached maximum exploitation, stop here
                        break

                    else:
                        if response.status == 500 and not saw_internal_error:
                            saw_internal_error = True
                            if parameter == "QUERY_STRING":
                                anom_msg = Anomaly.MSG_QS_500
                            else:
                                anom_msg = Anomaly.MSG_PARAM_500.format(parameter)

                            self.add_anom(
                                request_id=original_request.path_id,
                                category=Anomaly.ERROR_500,
                                level=Anomaly.HIGH_LEVEL,
                                request=mutated_request,
                                info=anom_msg,
                                parameter=parameter
                            )

                            self.log_orange("---")
                            self.log_orange(Anomaly.MSG_500, page)
                            self.log_orange(Anomaly.MSG_EVIL_REQUEST)
                            self.log_orange(mutated_request.http_repr())
                            self.log_orange("---")
                except (KeyboardInterrupt, RequestException) as exception:
                    yield exception

            yield original_request

    # TODO: should blindsql module ignore vulnerabilities that have previously been detected by the sql module ?
    def load_require(self, dependancies: list = None):
        if dependancies:
            for module in dependancies:
                if module.name == "sql":
                    self.excluded_get = module.vulnerable_get
                    self.excluded_post = module.vulnerable_post
