# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2025 Nicolas Surribas
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
from typing import Generator, Any, List, Tuple
from urllib.parse import urlparse

from wapitiCore.model.vulnerability import VulnerabilityInstance
from wapitiCore.net import Request, Response
from wapitiCore.definitions.secure_cookie import SecureCookieFinding
from wapitiCore.definitions.http_only import HttpOnlyFinding
from wapitiCore.main.log import log_red
from wapitiCore.language.vulnerability import LOW_LEVEL

INFO_COOKIE_HTTPONLY = "HttpOnly flag is not set on the cookie '{0}' set at '{1}'"
INFO_COOKIE_SECURE = "Secure flag is not set on the cookie: '{0}' set at '{1}'"


def _get_cookies_from_response(response: Response) -> List[Tuple[str, str, bool, bool]]:
    """
    Helper to extract Cookie objects from the 'Set-Cookie' headers of a response.
    This part might need specific implementation depending on your Response object structure.
    For now, let's assume a simplified parsing.
    """
    cookies_list = []
    set_cookie_headers = response.headers.get_list("set-cookie")

    for header_value in set_cookie_headers:
        # Basic parsing of the Set-Cookie header string
        # Example: "session_id=abc123; Path=/; HttpOnly; Domain=example.com; Expires=..."
        parts = header_value.split(";")

        # First part is name=value
        name_value_pair = parts[0].strip().split("=", 1)
        if len(name_value_pair) != 2:
            log_red(f"Could not parse cookie name/value from '{header_value}'")
            continue

        name = name_value_pair[0]

        # Initialize cookie attributes
        domain = ""
        # path = "/"
        secure = False
        httponly = False

        # Parse other attributes
        for part in parts[1:]:
            part = part.strip()
            lower_part = part.lower()

            if lower_part == "secure":
                secure = True
            elif lower_part == "httponly":
                httponly = True
            elif lower_part.startswith("domain="):
                domain = part.split("=", 1)[1]
            # elif lower_part.startswith("path="):
            #     path = part.split('=', 1)[1]

        # Determine the effective domain for the cookie.
        # If no domain is explicitly set in the cookie, it defaults to the request's host.
        if not domain:
            domain = urlparse(response.url).hostname

        cookies_list.append((name, domain, secure, httponly))

    return cookies_list


class ModuleCookieFlags:
    """
    Passively evaluates the security of cookies present in HTTP responses.
    """

    name = "cookieflags"

    def __init__(self):
        # To avoid reporting the same issue for the same cookie multiple times.
        # We will store identifiers of already reported cookies.
        # An identifier could be (cookie_name, cookie_domain, flag_type_missing)
        self._reported_cookies: set[tuple[str, str, str]] = set()

    def analyze(
        self, request: Request, response: Response
    ) -> Generator[VulnerabilityInstance, Any, None]:
        """
        Analyzes an HTTP response for insecure cookie flags.
        """
        cookies_from_response = _get_cookies_from_response(response)

        for (
            cookie_name,
            cookie_domain,
            secure_flag,
            httponly_flag,
        ) in cookies_from_response:
            # HttpOnly check
            if not httponly_flag:
                identifier = (cookie_name, cookie_domain, "HttpOnly")
                if identifier not in self._reported_cookies:
                    self._reported_cookies.add(identifier)
                    log_red(INFO_COOKIE_HTTPONLY.format(cookie_name, request.url))
                    yield VulnerabilityInstance(
                        finding_class=HttpOnlyFinding,
                        request=request,
                        response=response,
                        info=INFO_COOKIE_HTTPONLY.format(cookie_name, request.url),
                        severity=LOW_LEVEL,  # HttpOnly is generally Low severity
                    )

            # Secure flag check
            if not secure_flag:
                identifier = (cookie_name, cookie_domain, "Secure")
                if identifier not in self._reported_cookies:
                    self._reported_cookies.add(identifier)
                    log_red(INFO_COOKIE_SECURE.format(cookie_name, request.url))
                    yield VulnerabilityInstance(
                        finding_class=SecureCookieFinding,
                        request=request,
                        response=response,
                        info=INFO_COOKIE_SECURE.format(cookie_name, request.url),
                        severity=LOW_LEVEL,  # Secure Flag is also Low severity
                    )
