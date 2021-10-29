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
from httpx import RequestError

from wapitiCore.main.log import log_red, log_verbose
from wapitiCore.attack.attack import Attack, Flags
from wapitiCore.language.vulnerability import Messages, _
from wapitiCore.definitions.redirect import NAME
from wapitiCore.net.web import Request


class ModuleRedirect(Attack):
    """Detect Open Redirect vulnerabilities."""
    # Won't work with PHP >= 4.4.2

    name = "redirect"
    MSG_VULN = _("Open Redirect")
    do_get = True
    do_post = False
    payloads = ("https://openbugbounty.org/", Flags())

    def __init__(self, crawler, persister, attack_options, stop_event):
        super().__init__(crawler, persister, attack_options, stop_event)
        self.mutator = self.get_mutator()

    async def attack(self, request: Request):
        page = request.path

        for mutated_request, parameter, __, __ in self.mutator.mutate(request):
            log_verbose(f"[¨] {mutated_request.url}")

            try:
                response = await self.crawler.async_send(mutated_request)
            except RequestError:
                self.network_errors += 1
                continue

            if any(url.startswith("https://openbugbounty.org/") for url in response.all_redirections):
                await self.add_vuln_low(
                    request_id=request.path_id,
                    category=NAME,
                    request=mutated_request,
                    parameter=parameter,
                    info=_("{0} via injection in the parameter {1}").format(self.MSG_VULN, parameter)
                )

                if parameter == "QUERY_STRING":
                    injection_msg = Messages.MSG_QS_INJECT
                else:
                    injection_msg = Messages.MSG_PARAM_INJECT

                log_red("---")
                log_red(
                    injection_msg,
                    self.MSG_VULN,
                    page,
                    parameter
                )
                log_red(Messages.MSG_EVIL_REQUEST)
                log_red(mutated_request.http_repr())
                log_red("---")
