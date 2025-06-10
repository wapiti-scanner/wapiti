# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2020-2025 Nicolas Surribas
# Copyright (C) 2021-2025 Cyberwatch
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

from typing import Generator, Any, Tuple

from wapitiCore.model.vulnerability import VulnerabilityInstance
from wapitiCore.net import Request, Response
from wapitiCore.net.csp_utils import csp_header_to_dict, CSP_CHECK_LISTS, check_policy_values
from wapitiCore.definitions.csp import CspFinding
from wapitiCore.main.log import log_red
from wapitiCore.language.vulnerability import LOW_LEVEL, MEDIUM_LEVEL

MSG_NO_CSP = "CSP is not set for URL: {0}"
MSG_CSP_MISSING = "CSP attribute \"{0}\" is missing for URL: {1}"
MSG_CSP_UNSAFE = "CSP \"{0}\" value is not safe for URL: {1}"


class ModuleCsp:
    """
    Passively evaluates the security level of Content Security Policies in HTTP responses.
    """
    name = "csp"

    def __init__(self):
        # We wait to avoid flooding the user with repeated CSP misconfiguration
        # Keep some identified cases here for each netloc
        self._reported_csp_issues: set[Tuple[str, str, str]] = set()

    def analyze(self, request: Request, response: Response) -> Generator[VulnerabilityInstance, Any, None]:
        """
        Analyzes an HTTP response for Content Security Policy (CSP) headers.
        """
        if "text/html" not in response.type:
            return

        csp_header_value = response.headers.get("Content-Security-Policy")

        if not csp_header_value:
            identifier = (request.netloc, "CSP", "Missing")

            if identifier not in self._reported_csp_issues:
                self._reported_csp_issues.add(identifier)
                log_red(MSG_NO_CSP.format(request.url))
                yield VulnerabilityInstance(
                    finding_class=CspFinding,
                    request=request,
                    response=response,
                    info=MSG_NO_CSP.format(request.url),
                    severity=LOW_LEVEL,
                )
        else:
            csp_dict = csp_header_to_dict(csp_header_value)

            for policy_name in CSP_CHECK_LISTS:
                result = check_policy_values(policy_name, csp_dict)

                info = None
                severity = LOW_LEVEL  # Default severity

                if result == -1:  # Policy is missing
                    info = MSG_CSP_MISSING.format(policy_name, request.url)
                    if policy_name in ["script-src", "object-src", "base-uri", "frame-ancestors"]:
                        severity = MEDIUM_LEVEL
                elif result == 0:
                    info = MSG_CSP_UNSAFE.format(policy_name, request.url)
                    if policy_name in ["script-src", "object-src"]:
                        severity = MEDIUM_LEVEL

                if info:
                    identifier = (request.netloc, policy_name, "Unsafe" if result == 0 else "Missing")
                    if identifier not in self._reported_csp_issues:
                        self._reported_csp_issues.add(identifier)
                        log_red(info)
                        yield VulnerabilityInstance(
                            finding_class=CspFinding,
                            request=request,
                            response=response,
                            info=info,
                            severity=severity,
                        )
