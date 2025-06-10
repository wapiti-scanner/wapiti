#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2023-2024 Cyberwatch
# Copyright (C) 2025 Nicolas Surribas
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
from urllib.parse import urlparse

from wapitiCore.net import Request
from wapitiCore.net.response import Response
from wapitiCore.model.vulnerability import VulnerabilityInstance
from wapitiCore.definitions.https_redirect import HstsFinding
from wapitiCore.language.vulnerability import LOW_LEVEL, MEDIUM_LEVEL
from wapitiCore.main.log import log_orange, log_red


class ModuleHttpsRedirect:
    """Check for HTTPS redirections on sensitive HTTP requests."""
    name = "https_redirect"

    MSG_SENSITIVE = "Sensitive data ({reason}) was sent over an unencrypted HTTP connection to {url}. "
    MSG_SENSITIVE_NO_REDIRECT = MSG_SENSITIVE + "The server did not enforce HTTPS."
    MSG_SENSITIVE_REDIRECT_TO_HTTPS = (
            MSG_SENSITIVE +
            "The server redirected to an HTTPS URL, but the initial data and the redirection were exposed."
    )
    MSG_SENSITIVE_REDIRECT_TO_HTTP = MSG_SENSITIVE + (
        "The server redirected, but not to an HTTPS URL, leaving the initial data and the redirection exposed."
    )
    MSG_REASON_REQUEST_COOKIES = "cookie in the request"
    MSG_REASON_REQUEST_GET = "GET parameters"
    MSG_REASON_REQUEST_POST = "POST data"
    MSG_REASON_RESPONSE_COOKIES = "cookie in the response"

    MSG_INFO_NO_REDIRECT = "No HTTPS redirection for this host. All HTTP requests are served in clear text."

    def __init__(self):
        """
        Init the module along with the set of reported findings.
        """
        self._reported_findings_sensitive: set[Tuple[str, str, str]] = set()
        self._reported_info_non_sensitive: set[str] = set()

    def _get_sensitive_reason(self, request: Request, response: Response) -> str:
        """
        Returns the most important reason why a request or response is considered sensitive
        as a string.
        """
        if bool(response.headers.get("Set-Cookie")):
            return self.MSG_REASON_RESPONSE_COOKIES
        if bool(request.headers.get("Cookie")):
            return self.MSG_REASON_REQUEST_COOKIES
        if request.method == "POST" and (request.post_params or request.file_params):
            return self.MSG_REASON_REQUEST_POST
        if bool(request.get_params):
            return self.MSG_REASON_REQUEST_GET

        return ""

    def analyze(self, request: Request, response: Response) -> Generator[VulnerabilityInstance, Any, None]:
        """
        Analyze an HTTP request/response for HTTPS redirection issues.
        """
        if request.scheme != "http":
            return

        host = urlparse(request.url).netloc
        sensitive_reason = self._get_sensitive_reason(request, response)

        if sensitive_reason:
            if response.is_redirect and urlparse(response.redirection_url).scheme == "https":
                finding_type = "redirect_to_https"
            elif response.is_redirect:
                finding_type = "redirect_to_http"
            else:
                finding_type = "no_redirect"

            identifier = (host, sensitive_reason, finding_type)
            if identifier not in self._reported_findings_sensitive:
                self._reported_findings_sensitive.add(identifier)

                # Report the vulnerability based on the type of redirection
                if finding_type == "redirect_to_https":
                    full_info = self.MSG_SENSITIVE_REDIRECT_TO_HTTPS.format(reason=sensitive_reason, url=request.url)
                    severity = MEDIUM_LEVEL
                elif finding_type == "redirect_to_http":
                    full_info = self.MSG_SENSITIVE_REDIRECT_TO_HTTP.format(reason=sensitive_reason, url=request.url)
                    severity = LOW_LEVEL
                else:  # "no_redirect"
                    full_info = self.MSG_SENSITIVE_NO_REDIRECT.format(reason=sensitive_reason, url=request.url)
                    severity = MEDIUM_LEVEL

                log_red(full_info)
                yield VulnerabilityInstance(
                    finding_class=HstsFinding,
                    request=request,
                    response=response,
                    info=full_info,
                    severity=severity,
                )
        elif "html" in response.headers.get("content-type", "html").lower():
            # Non-sensitive case, check for general lack of HTTPS redirection
            if host not in self._reported_info_non_sensitive:
                self._reported_info_non_sensitive.add(host)
                if not response.is_redirect or urlparse(response.redirection_url).scheme != "https":
                    log_orange(f"Host {host} serves HTTP content without redirecting to HTTPS.")
                    yield VulnerabilityInstance(
                        finding_class=HstsFinding,
                        request=request,
                        response=response,
                        info=self.MSG_INFO_NO_REDIRECT,
                        severity=LOW_LEVEL,
                    )
