# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2020-2026 Nicolas Surribas
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
from typing import List, Optional, Type, Generator, Any, Callable

from wapitiCore.attack.modules.passive.base import PassiveModule
from wapitiCore.definitions import FindingBase
from wapitiCore.net.web import urlparse
from wapitiCore.net.response import Response
from wapitiCore.net import Request
from wapitiCore.model.vulnerability import VulnerabilityInstance
from wapitiCore.definitions.http_headers import ClickjackingFinding, MimeTypeConfusionFinding, HstsFinding
from wapitiCore.main.log import log_red, log_orange
from wapitiCore.language.vulnerability import LOW_LEVEL

HSTS_NOT_SET = "Strict-Transport-Security is not set"
XCONTENT_TYPE_NOT_SET = "X-Content-Type-Options is not set"
XFRAME_OPTIONS_NOT_SET = "X-Frame-Options is not set"
INVALID_HSTS = (
    "Strict-Transport-Security has an invalid value "
    "(expected a single 'max-age' directive with a positive integer)"
)
INVALID_XCONTENT_TYPE = "X-Content-Type-Options has an invalid value ('nosniff' not found)"
INVALID_XFRAME_OPTIONS = "X-Frame-Options has an invalid value ('deny' or 'sameorigin' or not found)"

# A per-header validator answers "is the received value acceptable?" for one header.
HeaderValidator = Callable[[Response, str], bool]


def _contains_any(check_list: List[str]) -> HeaderValidator:
    """Build a validator accepting a header value containing one of the expected tokens."""

    def validator(response: Response, header_name: str) -> bool:
        return any(token in response.headers[header_name].lower() for token in check_list)

    return validator


def _is_valid_hsts(response: Response, header_name: str) -> bool:
    """Return True when the first STS field carries exactly one usable max-age.

    Wapiti reports header posture, it does not behave as a user agent: the other
    directives are ignored, whatever their syntax, and only max-age is looked at.
    """
    fields = response.headers.get_list(header_name)
    if not fields:
        return False

    # RFC 6797 section 8.1: only the first field is processed, hence get_list()
    # rather than the comma-joined value returned by __getitem__.
    values = []
    for directive in fields[0].split(";"):
        name, _, value = directive.partition("=")
        if name.strip().lower() == "max-age":
            values.append(value.strip())

    if len(values) != 1:
        return False

    value = values[0]
    if len(value) > 1 and value[0] == '"' and value[-1] == '"':
        value = value[1:-1].strip()

    # A non-zero ASCII decimal integer, checked with str methods only so that an
    # oversized value is accepted without any int() conversion.
    return value.isascii() and value.isdigit() and value.strip("0") != ""


class ModuleHttpHeaders(PassiveModule):
    """
    Passively evaluates the security of HTTP headers present in HTTP responses.
    """
    name = "http_headers"

    check_list_xframe = ["deny", "sameorigin"]
    check_list_xcontent = ["nosniff"]

    headers_to_check = {
        "X-Frame-Options": {
            "validator": _contains_any(check_list_xframe),
            "info": {"error": XFRAME_OPTIONS_NOT_SET, "warning": INVALID_XFRAME_OPTIONS},
            "finding": ClickjackingFinding,
        },
        "X-Content-Type-Options": {
            "validator": _contains_any(check_list_xcontent),
            "info": {"error": XCONTENT_TYPE_NOT_SET, "warning": INVALID_XCONTENT_TYPE},
            "finding": MimeTypeConfusionFinding,
        },
        "Strict-Transport-Security": {
            "validator": _is_valid_hsts,
            "info": {"error": HSTS_NOT_SET, "warning": INVALID_HSTS},
            "finding": HstsFinding,
        }
    }

    @staticmethod
    def is_set(response: Response, header_name: str) -> bool:
        return header_name in response.headers

    def _check_header(
        self,
        response: Response,
        request: Request,
        header_name: str,
        validator: HeaderValidator,
        info_messages: dict[str, str],
        finding_class: Type[FindingBase],
    ) -> Optional[VulnerabilityInstance]:
        """
        Helper method to check a single header and return a finding if necessary.
        """
        target = urlparse(request.url).netloc

        if not self.is_set(response, header_name):
            finding_info = info_messages["error"]
            # A missing header is a single posture (empty value), so it is reported
            # once per (netloc, header), as before.
            identifier = (target, header_name, "not_set", "")

            if self.should_report(identifier, finding_class):
                log_red(f"{finding_info} on {request.url}")
                return VulnerabilityInstance(
                    finding_class=finding_class,
                    request=request,
                    response=response,
                    info=finding_info,
                    severity=LOW_LEVEL,
                )
        elif not validator(response, header_name):
            finding_info = info_messages["warning"]
            # Include the offending value so pages that carry *different* invalid values
            # for the same header each surface, while identical ones are deduplicated.
            posture = response.headers[header_name].strip().lower()
            identifier = (target, header_name, "invalid_value", posture)
            if self.should_report(identifier, finding_class):
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
                header_data["validator"],
                header_data["info"],
                header_data["finding"],
            )
            if finding:
                yield finding
