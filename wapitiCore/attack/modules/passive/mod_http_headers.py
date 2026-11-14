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
import re
from typing import List, Optional, Type, Generator, Any

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

_HSTS_MAX_AGE = re.compile(r"[0-9]+")
_HSTS_TOKEN = re.compile(r"[A-Za-z0-9!#$%&'*+.^_`|~-]+")
_QUOTED_STRING = re.compile(r'"((?:[^"\\\x00-\x1f\x7f]|\\[\x20-\x7e])*)"')


def _split_hsts_directives(value: str) -> Optional[List[str]]:
    """Split an STS field value on ';' outside quoted-strings.

    Returns None when a quoted-string is left unterminated, making the whole
    field syntactically invalid (RFC 6797 section 8.1).
    """
    parts: List[str] = []
    current: List[str] = []
    quoted = escaped = False
    for character in value:
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
        elif character == '"':
            quoted = True
        elif character == ";":
            parts.append("".join(current))
            current = []
            continue
        current.append(character)
    if quoted:
        return None
    parts.append("".join(current))
    return parts


def _unquote_hsts_value(value: str) -> Optional[str]:
    """Strip a quoted-string (removing quoted-pair escapes) or return a token as-is."""
    value = value.strip()
    if not value.startswith('"'):
        return value
    match = _QUOTED_STRING.fullmatch(value)
    if match is None:
        return None
    return re.sub(r"\\([\x20-\x7e])", r"\1", match.group(1))


def _valid_hsts_directive(element: str) -> Optional[tuple[str, Optional[str]]]:
    """Return (lowercase name, max-age digits) or None when the directive is invalid."""
    name, separator, raw_value = element.partition("=")
    name = name.strip()
    if _HSTS_TOKEN.fullmatch(name) is None:
        return None
    directive = name.lower()
    if directive == "max-age":
        digits = _unquote_hsts_value(raw_value) if separator else None
        return (directive, digits) if digits is not None and _HSTS_MAX_AGE.fullmatch(digits) else None
    if directive == "includesubdomains":
        return (directive, None) if not separator else None
    if separator:
        value = raw_value.strip()
        if value.startswith('"'):
            return (directive, None) if _QUOTED_STRING.fullmatch(value) else None
        return (directive, None) if _HSTS_TOKEN.fullmatch(value) else None
    return directive, None


def _has_valid_hsts(value: str) -> bool:
    """Return True when every directive is valid and max-age is a positive integer."""
    if "\r" in value or "\n" in value:
        return False
    elements = _split_hsts_directives(value)
    if elements is None:
        return False

    seen = set()
    max_age: Optional[str] = None
    for element in elements:
        if not element.strip():
            continue
        parsed = _valid_hsts_directive(element)
        if parsed is None:
            return False
        directive, digits = parsed
        if directive in seen:
            return False
        seen.add(directive)
        if digits is not None:
            max_age = digits

    return max_age is not None and bool(max_age.lstrip("0"))


class ModuleHttpHeaders(PassiveModule):
    """
    Passively evaluates the security of HTTP headers present in HTTP responses.
    """
    name = "http_headers"

    check_list_xframe = ["deny", "sameorigin"]
    check_list_xcontent = ["nosniff"]
    # HSTS is validated structurally (see _has_valid_hsts), not by substring lookup.
    check_list_hsts: List[str] = []

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

    @staticmethod
    def is_set(response: Response, header_name: str) -> bool:
        return header_name in response.headers

    @staticmethod
    def contains(response: Response, header_name: str, check_list: List[str]) -> bool:
        if header_name == "Strict-Transport-Security":
            # RFC 6797 section 8.1: only the first STS field is processed. Asking
            # for the list without comma splitting prevents a merged "invalid,
            # valid" value from rescuing the invalid first field.
            values = response.headers.get_list(header_name)
            return bool(values) and _has_valid_hsts(values[0])
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
        elif not self.contains(response, header_name, check_list):
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
                header_data["list"],
                header_data["info"],
                header_data["finding"],
            )
            if finding:
                yield finding
