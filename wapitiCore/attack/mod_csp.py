# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2020-2023 Nicolas Surribas
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
from typing import Optional

from httpx import RequestError

from wapitiCore.attack.attack import Attack
from wapitiCore.net import Request
from wapitiCore.net.response import Response
from wapitiCore.net.csp_utils import csp_header_to_dict, CSP_CHECK_LISTS
from wapitiCore.definitions.csp import NAME, WSTG_CODE
from wapitiCore.main.log import log_red

MSG_NO_CSP = "CSP is not set"

INFO_UNSAFE_INLINE = "\"unsafe-inline\" in \"{0}\" directive allows the execution of unsafe in-page scripts and event\
 handlers."
INFO_UNSAFE_EVAL = "\"unsafe-eval\" in \"{0}\" directive allows the execution of code injected into DOM APIs such as\
 eval()."
INFO_DATA_HTTP_HTTPS = "value \"{0}\" URI in \"{1}\" allows the execution of unsafe scripts."
INFO_ALLOW_ALL = "\"{0}\" directive should not allow \"*\" as source"
INFO_UNSAFE_OBJECT_SRC = "unsafe values \"{0}\" other then \"none\" identified in \"object-src\""
INFO_UNSAFE_BASE_URI = "unsafe values \"{0}\" other then \"none\" and \"self\" identified in \"base-uri\""
INFO_UNDEFINED_DIRECTIVE = "directive \"{0}\" is not defined"

# This module check the basics recommendations of CSP
def check_policy(policy_name, csp_dict):
    """
    This function return the unsafe values for each directive of the tested CSP
    """
    info = ""

    if policy_name not in csp_dict and "default-src" not in csp_dict:
        log_red(INFO_UNDEFINED_DIRECTIVE.format(policy_name))
        info += INFO_UNDEFINED_DIRECTIVE.format(policy_name) + "\n"

    # The HTTP CSP "default-src" directive serves as a fallback for the other CSP fetch directives.
    # https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/default-src
    policy_values = csp_dict.get(policy_name) or csp_dict["default-src"]
    info = ""
    # If the tested element is default-src or script-src, we must ensure that none of this unsafe values are present
    if policy_name in ["default-src", "script-src"]:
        for unsafe_value in CSP_CHECK_LISTS[policy_name]:
            if unsafe_value in policy_values:
                if unsafe_value == "unsafe-inline":
                    log_red(INFO_UNSAFE_INLINE.format(policy_name))
                    info += INFO_UNSAFE_INLINE.format(policy_name) + "\n"
                elif unsafe_value in ("data:", "http:", "https:"):
                    log_red(INFO_DATA_HTTP_HTTPS.format(unsafe_value, policy_name))
                    info += INFO_DATA_HTTP_HTTPS.format(unsafe_value, policy_name) + "\n"
                elif unsafe_value == "*":
                    log_red(INFO_ALLOW_ALL.format(policy_name))
                    info += INFO_ALLOW_ALL.format(policy_name) + "\n"
                elif unsafe_value == "unsafe-eval":
                    log_red(INFO_UNSAFE_EVAL.format(policy_name))
                    info += INFO_UNSAFE_EVAL.format(policy_name) + "\n"

    # If the tested element is none of the previous list, we must ensure that one of this safe values is present
    else:
        for safe_value in CSP_CHECK_LISTS[policy_name]:
            if safe_value not in policy_values:
                if policy_name == "object-src":
                    log_red(INFO_UNSAFE_OBJECT_SRC.format(policy_values))
                    info += INFO_UNSAFE_OBJECT_SRC.format(policy_values) + "\n"
                elif policy_name == "base-uri":
                    log_red(INFO_UNSAFE_BASE_URI.format(policy_values))
                    info += INFO_UNSAFE_BASE_URI.format(policy_values) + "\n"

    return info


class ModuleCsp(Attack):
    """Evaluate the security level of Content Security Policies of the web server."""
    name = "csp"

    async def must_attack(self, request: Request, response: Optional[Response] = None):
        if self.finished:
            return False

        if request.method == "POST":
            return False

        return request.url == await self.persister.get_root_url()

    async def attack(self, request: Request, response: Optional[Response] = None):
        self.finished = True
        request_to_root = Request(request.url)

        try:
            response: Response = await self.crawler.async_send(request_to_root, follow_redirects=True)
        except RequestError:
            self.network_errors += 1
            return

        if "Content-Security-Policy" not in response.headers:
            log_red(MSG_NO_CSP)
            await self.add_vuln_low(
                category=NAME,
                request=request_to_root,
                info=MSG_NO_CSP,
                wstg=WSTG_CODE,
                response=response
            )
        else:
            csp_dict = csp_header_to_dict(response.headers["Content-Security-Policy"])
            info = ""
            for policy_name in CSP_CHECK_LISTS:
                info += check_policy(policy_name, csp_dict)

            await self.add_vuln_low(
                category=NAME,
                request=request,
                info=info,
                wstg=WSTG_CODE,
                response=response
            )
