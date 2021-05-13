#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti.sourceforge.io)
# Copyright (C) 2008-2021 Nicolas Surribas
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

from httpx import ReadTimeout, HTTPStatusError, RequestError

from wapitiCore.attack.attack import Attack, Flags
from wapitiCore.language.vulnerability import Messages, MEDIUM_LEVEL, LOW_LEVEL, _
from wapitiCore.definitions.crlf import NAME
from wapitiCore.net.web import Request


class mod_crlf(Attack):
    """Detect Carriage Return Line Feed (CRLF) injection vulnerabilities."""
    # Won't work with PHP >= 4.4.2

    name = "crlf"
    MSG_VULN = _("CRLF Injection")
    do_get = True
    do_post = True
    payloads = (quote("http://www.google.fr\r\nwapiti: 3.0.5 version"), Flags())

    def __init__(self, crawler, persister, logger, attack_options, stop_event):
        super().__init__(crawler, persister, logger, attack_options, stop_event)
        self.mutator = self.get_mutator()

    async def attack(self, request: Request):
        page = request.path

        for mutated_request, parameter, _payload, _flags in self.mutator.mutate(request):
            if self.verbose == 2:
                print("[¨] {0}".format(mutated_request.url))

            try:
                response = await self.crawler.async_send(mutated_request)
            except ReadTimeout:
                self.network_errors += 1
                self.add_anom(
                    request_id=request.path_id,
                    category=Messages.RES_CONSUMPTION,
                    level=MEDIUM_LEVEL,
                    request=mutated_request,
                    parameter=parameter,
                    info="Timeout (" + parameter + ")"
                )

                self.log_orange("---")
                self.log_orange(Messages.MSG_TIMEOUT, page)
                self.log_orange(Messages.MSG_EVIL_REQUEST)
                self.log_orange(mutated_request.http_repr())
                self.log_orange("---")
            except HTTPStatusError:
                self.network_errors += 1
                self.log(_("Error: The server did not understand this request"))
            except RequestError:
                self.network_errors += 1
            else:
                if "wapiti" in response.headers:
                    self.add_vuln(
                        request_id=request.path_id,
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
