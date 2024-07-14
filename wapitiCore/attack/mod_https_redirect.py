#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2023-2024 Cyberwatch
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
from functools import lru_cache
from typing import Optional
from urllib.parse import urlparse, urlunparse
import socket

from httpx import RequestError

from wapitiCore.attack.attack import Attack
from wapitiCore.definitions.https_redirect import HstsFinding
from wapitiCore.definitions.internal_error import InternalErrorFinding
from wapitiCore.language.vulnerability import Messages
from wapitiCore.net import Request
from wapitiCore.net.response import Response
from wapitiCore.main.log import log_red, log_orange


@lru_cache
def test_port(address: str, dest_port: int, timeout: float = None) -> bool:
    """Check if dest_port is open on address"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((address, dest_port)) == 0:
                return True
            return False
    except (OSError, ValueError):
        return False


# This module check whether HTTP requests are redirected to HTTPS or not
class ModuleHttpsRedirect(Attack):
    """Check for HTTPS redirections."""
    name = "https_redirect"
    MSG_VULN_NO_REDIRECT = "No HTTPS redirection"
    MSG_VULN_REDIRECT = "Redirected to HTTP"

    async def must_attack(self, request: Request, response: Optional[Response] = None):
        if self.finished:
            return False

        if response.is_directory_redirection:
            return False

        url = urlparse(request.url)
        if not test_port(url.hostname, url.port or 80, self.crawler_configuration.timeout):
            log_orange(f"Port {url.port or 80} appears to be closed on {url.hostname}")
            self.finished = True
            return False
        return True

    async def attack(self, request: Request, response: Optional[Response] = None):
        url = urlparse(request.url)

        is_http = False
        if url.scheme == "http":
            log_red(f"HTTP URL provided : {request.url}")
            is_http = True
            # if http url is provided we will stop the module after the first request
            # this will allow to add only one vuln for http target
            self.finished = True

        if url.port:
            log_orange(f"Specific port provided : {url.port}")
            # if specific port (different from 80/443) is provided
            # we will stop the module after the first request
            # if service exposed requires SSL/TLS, we will get 400 errors
            self.finished = True

        # ensure targeting http url
        http_url = request.url if is_http else urlunparse(url._replace(scheme='http'))
        http_request = Request(
            http_url, request.method, request.get_params,
            request.post_params, request.file_params, request.encoding,
            request.enctype, request.referer, request.link_depth
        )

        try:
            http_response: Response = await self.crawler.async_send(http_request, follow_redirects=False)
        except RequestError:
            self.network_errors += 1
            return

        if http_response.is_success:
            log_red(f"URL {http_response.url} does not redirect to https")
            await self.add_low(
                finding_class=HstsFinding,
                request=http_request,
                info=self.MSG_VULN_NO_REDIRECT,
                response=http_response
            )

        elif http_response.is_redirect:
            # add vuln if redirected to url without https
            # might cause false positive in case of multiple redirections
            if urlparse(http_response.headers["location"]).scheme != "https":
                log_red("Location : " + http_response.headers["location"])
                await self.add_low(
                    finding_class=HstsFinding,
                    request=http_request,
                    info=f"{self.MSG_VULN_REDIRECT} location : {http_response.headers['location']}",
                    response=http_response
                )
        else:
            log_orange(http_response.url + " responded with code " + str(http_response.status))

            if http_response.status >= 500:
                await self.add_medium(
                    finding_class=InternalErrorFinding,
                    request=http_request,
                    info=Messages.MSG_500.format(http_response.url + " : " + str(http_response.status)),
                    response=http_response
                )
