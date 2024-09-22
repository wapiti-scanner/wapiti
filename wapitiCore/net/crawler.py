#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2006-2023 Nicolas SURRIBAS
# Copyright (C) 2020-2024 Cyberwatch
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

# Standard libraries
from urllib.parse import urlparse, urlunparse
import warnings
import functools
from typing import Dict
import asyncio
import ssl

# Third-parties
import httpx

# Internal libraries
from wapitiCore.net import web
from wapitiCore.net.classes import CrawlerConfiguration

from wapitiCore.net.response import Response

warnings.filterwarnings(action='ignore', category=UserWarning, module='bs4')


def retry(delay=1, times=3):
    """
    A decorator for retrying a request with a specified delay in case of Timeout exception

    Parameter List
    -------------
    :param delay: Amount of delay (seconds) needed between successive retries.
    :param times: no of times the function should be retried
    """

    def outer_wrapper(function):
        @functools.wraps(function)
        async def inner_wrapper(*args, **kwargs):
            final_excep = None
            for counter in range(times):
                if counter > 0:
                    await asyncio.sleep(delay)

                try:
                    value = await function(*args, **kwargs)
                    return value
                except httpx.NetworkError as exception:
                    raise exception
                except httpx.TimeoutException as exception:
                    final_excep = exception

            if final_excep is not None:
                raise final_excep

        return inner_wrapper

    return outer_wrapper


async def drop_cookies_from_request(request):
    """Removes the Cookie header from the request."""
    # Would have been better to remove the cookie from the response but it doesn't seem to work.
    # Result should be the same though.
    try:
        del request.headers["cookie"]
    except KeyError:
        pass


class AsyncCrawler:
    SUCCESS = 0
    TIMEOUT = 1
    HTTP_ERROR = 2
    INVALID_URL = 3
    CONNECT_ERROR = 4
    SSL_ERROR = 5
    UNKNOWN_ERROR = 6

    def __init__(
            self,
            base_request: web.Request,
            client: httpx.AsyncClient,
            timeout: float = 10.0,
    ):
        self._base_request = base_request
        self._client = client
        self._timeout = httpx.Timeout(timeout, read=None)

        self.is_logged_in = False
        self.auth_url: str = self._base_request.url

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
        return False

    @classmethod
    def with_configuration(cls, configuration: CrawlerConfiguration) -> "AsyncCrawler":
        headers = {
            "User-Agent": configuration.user_agent,
            "Accept-Language": "en-US",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
        }

        headers.update(configuration.headers or {})

        if not configuration.compression:
            headers["Accept-Encoding"] = "identity"

        ssl_context = httpx.create_ssl_context()
        ssl_context.check_hostname = configuration.secure
        ssl_context.verify_mode = ssl.CERT_REQUIRED if configuration.secure else ssl.CERT_NONE

        # Allows dead protocols like SSL and TLS1
        ssl_context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED

        auth = None
        if configuration.http_credential:
            if configuration.http_credential.method == "basic":
                auth = httpx.BasicAuth(
                    configuration.http_credential.username,
                    configuration.http_credential.password
                )
            elif configuration.http_credential.method == "digest":
                auth = httpx.DigestAuth(
                    configuration.http_credential.username,
                    configuration.http_credential.password
                )
            elif configuration.http_credential.method == "ntlm":
                # https://github.com/ulodciv/httpx-ntlm
                from httpx_ntlm import HttpNtlmAuth
                auth = HttpNtlmAuth(
                    configuration.http_credential.username,  # username should be in the form "domain\user"
                    configuration.http_credential.password
                )

        client = httpx.AsyncClient(
            auth=auth,
            headers=headers,
            cookies=configuration.cookies,
            verify=ssl_context,
            proxies=cls._proxy_url_to_dict(configuration.proxy),
            timeout=configuration.timeout,
            event_hooks={"request": [drop_cookies_from_request]} if configuration.drop_cookies else None,
        )

        client.max_redirects = 5
        return cls(configuration.base_request, client, configuration.timeout)

    @staticmethod
    def _proxy_url_to_dict(proxy: str) -> Dict[str, str]:
        """Set a proxy to use for HTTP requests."""
        if not proxy:
            return {}

        url_parts = urlparse(proxy)
        protocol = url_parts.scheme.lower()

        if protocol not in ("http", "https", "socks", "socks5"):
            raise ValueError(f"Unknown proxy type: {protocol}")

        if protocol == "socks":
            protocol = "socks5"

        return {
            "http://": urlunparse((protocol, url_parts.netloc, '/', '', '', '')),
            "https://": urlunparse((protocol, url_parts.netloc, '/', '', '', '')),
        }

    @property
    def timeout(self):
        return self._timeout

    @property
    def user_agent(self):
        """Getter for user-agent property"""
        return self._client.headers["User-Agent"]

    @user_agent.setter
    def user_agent(self, value: str):
        """Setter for user-agent property"""
        if not isinstance(value, str):
            raise TypeError("Invalid type for User-Agent. Type str required.")

        self._client.headers["User-Agent"] = value

    @property
    def headers(self) -> httpx.Headers:
        """Returns the headers kept on the HTTP client"""
        return self._client.headers

    @property
    def cookie_jar(self):
        """Getter for session cookies (returns a Cookies object)"""
        return self._client.cookies.jar

    @retry(delay=1, times=3)
    async def async_get(
            self,
            resource: web.Request,
            follow_redirects: bool = False,
            headers: dict = None,
            stream: bool = False,
            timeout: float = None,
    ) -> Response:
        """Fetch the given url, returns a Response object on success, None otherwise.
        If None is returned, the error code can be obtained using the error_code property.

        @param resource: URL to get.
        @type resource: web.Request
        @param follow_redirects: If set to True, responses with a 3XX code and a Location header will be followed.
        @type follow_redirects: bool
        @param headers: Dictionary of additional headers to send with the request.
        @type headers: dict
        @type stream: bool
        @type timeout: float
        @rtype: Response
        """
        timeout = self.timeout if timeout is None else httpx.Timeout(timeout)
        request = self._client.build_request("GET", resource.url, headers=headers, timeout=timeout)
        try:
            response = await self._client.send(
                request, stream=stream, follow_redirects=follow_redirects
            )
        except httpx.TransportError as exception:
            if "Read timed out" in str(exception):
                raise httpx.ReadTimeout("Request time out", request=None)

            raise exception

        return Response(response)

    @retry(delay=1, times=3)
    async def async_request(
            self,
            method: str,
            form: web.Request,
            follow_redirects: bool = False,
            headers: dict = None,
            stream: bool = False,
            timeout: float = None,
    ) -> Response:
        """Submit the given form, returns a Response on success, None otherwise.

        @type method: str
        @type form: web.Request
        @type follow_redirects: bool
        @type headers: dict
        @type stream: bool
        @type timeout: float
        @rtype: Response
        """
        form_headers = {}

        if form.enctype and not form.is_multipart:
            form_headers = {"Content-Type": form.enctype}

        if isinstance(headers, (dict, httpx.Headers)) and headers:
            form_headers.update(headers)

        if form.referer:
            form_headers["referer"] = form.referer

        if form.is_multipart or "urlencoded" in form.enctype:
            file_params = form.file_params
            post_params = form.post_params
        else:
            file_params = None
            post_params = form.post_params

        content = None

        if post_params:
            if isinstance(post_params, str):
                content = post_params
                post_params = None
            else:
                content = None
                post_params = dict(post_params)
        else:
            post_params = None

        request = self._client.build_request(
            method,
            form.path,
            params=form.get_params,
            data=post_params,  # httpx expects a dict, hope to see more types soon
            content=content,
            files=file_params,
            headers=form_headers,
            timeout=self.timeout if timeout is None else httpx.Timeout(timeout)
        )
        try:
            response = await self._client.send(
                request, stream=stream, follow_redirects=follow_redirects
            )
        except httpx.TransportError as exception:
            if "Read timed out" in str(exception):
                raise httpx.ReadTimeout("Request time out", request=None)

            raise exception

        return Response(response)

    async def async_send(
            self,
            request: web.Request,
            headers: dict = None,
            follow_redirects: bool = False,
            stream: bool = False,
            timeout: float = None
    ) -> Response:
        if request.method == "GET":
            response = await self.async_get(
                request,
                headers=headers,
                follow_redirects=follow_redirects,
                stream=stream,
                timeout=timeout
            )
        else:
            response = await self.async_request(
                request.method,
                request,
                headers=headers,
                follow_redirects=follow_redirects,
                stream=stream,
                timeout=timeout
            )

        request.set_cookies(self._client.cookies)
        request.set_headers(response.sent_headers)
        return response

    async def close(self):
        await self._client.aclose()
