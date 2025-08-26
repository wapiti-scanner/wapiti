# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2020-2025 Nicolas Surribas
# Copyright (C) 2021-2024 Cyberwatch
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
from typing import List, Optional, Type, Generator, Any, Tuple
from urllib.parse import urlparse

from wapitiCore.definitions import FindingBase
from wapitiCore.net.response import Response
from wapitiCore.net import Request
from wapitiCore.model.vulnerability import VulnerabilityInstance
from wapitiCore.definitions.http_headers import ClickjackingFinding, MimeTypeConfusionFinding, HstsFinding
from wapitiCore.main.log import log_red, log_orange
from wapitiCore.language.vulnerability import LOW_LEVEL

HSTS_NOT_SET = "Strict-Transport-Security is not set"
XCONTENT_TYPE_NOT_SET = "X-Content-Type-Options is not set"
XFRAME_OPTIONS_NOT_SET = "X-Frame-Options is not set"
INVALID_HSTS = "Strict-Transport-Security has an invalid value ('max-age' not found)"
INVALID_XCONTENT_TYPE = "X-Content-Type-Options has an invalid value ('nosniff' not found)"
INVALID_XFRAME_OPTIONS = "X-Frame-Options has an invalid value ('deny' or 'sameorigin' or not found)"


class ModuleHttpHeaders:
    """
    Passively evaluates the security of HTTP headers present in HTTP responses.
    """
    name = "http_headers"

    check_list_xframe = ["deny", "sameorigin"]
    check_list_xcontent = ["nosniff"]
    check_list_hsts = ["max-age="]

    headers_to_check = {
        "X-Frame-Options": {
            "list": check_list_xframe,
            "info": {"error": XFRAME_OPTIONS_NOT_SET, "warning": INVALID_XFRAME_OPTIONS},
            "finding": ClickjackingFinding,
        },
        "X-Content-Type-Options": {
            "list": check_list_xcontent,
            "info": {"error": XCONTENT_TYPE_NOT_SET, "warning": INVALID_XCONTENT_TYPE},
            "finding": MimeTypeConfusionFinding,
        },
        "Strict-Transport-Security": {
            "list": check_list_hsts,
            "info": {"error": HSTS_NOT_SET, "warning": INVALID_HSTS},
            "finding": HstsFinding,
        }
    }

    def __init__(self):
        self._reported_findings: set[Tuple[str, str, str]] = set()


    @staticmethod
    def is_set(response: Response, header_name: str) -> bool:
        return header_name in response.headers

    @staticmethod
    def contains(response: Response, header_name: str, check_list: List[str]) -> bool:
        if header_name in response.headers:
            return any(element in response.headers[header_name].lower() for element in check_list)
        return False

    def _check_header(
        self,
        response: Response,
        request: Request,
        header_name: str,
        check_list: List[str],
        info_messages: dict[str, str],
        finding_class: Type[FindingBase],
    ) -> Optional[VulnerabilityInstance]:
        """
        Helper method to check a single header and return a finding if necessary.
        """
        target = urlparse(request.url).netloc

        if not self.is_set(response, header_name):
            finding_info = info_messages["error"]
            identifier = (target, header_name, "not_set")

            if identifier not in self._reported_findings:
                self._reported_findings.add(identifier)
                log_red(f"{finding_info} on {request.url}")
                return VulnerabilityInstance(
                    finding_class=finding_class,
                    request=request,
                    response=response,
                    info=finding_info,
                    severity=LOW_LEVEL,
                )
        elif not self.contains(response, header_name, check_list):
            finding_info = info_messages["warning"]
            identifier = (target, header_name, "invalid_value")
            if identifier not in self._reported_findings:
                self._reported_findings.add(identifier)
                log_orange(f"{finding_info} on {request.url}")
                return VulnerabilityInstance(
                    finding_class=finding_class,
                    request=request,
                    response=response,
                    info=finding_info,
                    severity=LOW_LEVEL,
                )

        return None


    def analyze(self, request: Request, response: Response) -> Generator[VulnerabilityInstance, Any, None]:
        """
        Analyzes an HTTP response for missing or insecure HTTP headers.
        """
        for header_name, header_data in self.headers_to_check.items():
            # Strict-Transport-Security is only relevant for HTTPS connections.
            # We check the schema of the request that generated this response.
            if header_name == "Strict-Transport-Security" and request.scheme != "https":
                continue

            finding = self._check_header(
                response,
                request,
                header_name,
                header_data["list"],
                header_data["info"],
                header_data["finding"],
            )
            if finding:
                yield finding
