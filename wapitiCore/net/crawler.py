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
from urllib.parse import urlunparse
import warnings
import functools
from typing import Optional, TYPE_CHECKING
import asyncio
import ssl

# Third-parties
import httpx
# https://github.com/ulodciv/httpx-ntlm
from httpx_ntlm import HttpNtlmAuth

# Internal libraries
from wapitiCore.net import web
from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net.web import urlparse

from wapitiCore.net.response import Response
from wapitiCore.main.log import logging, log_orange

if TYPE_CHECKING:
    from wapitiCore.net.scope import Scope

warnings.filterwarnings(action='ignore', category=UserWarning, module='bs4')

DEFAULT_PORTS = {"http": 80, "https": 443}


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
            scope: Optional["Scope"] = None,
    ):
        self._base_request = base_request
        self._client = client
        self._scope = scope
        # Hosts we already warned about when refusing to follow a redirect, to keep the log readable
        self._refused_redirect_hosts = set()
        # Apply the configured timeout to every phase, including read. A None read
        # timeout lets a stalled/slow-trickling server block `response.read()`
        # forever (the whole scan hangs unless --max-scan-time / --max-attack-time
        # is set). httpx's read timeout is per-chunk, so a large but progressing
        # download is unaffected; only a genuine stall (no data for `timeout`s)
        # is interrupted. This also matches the per-call timeout paths below,
        # which already build httpx.Timeout(timeout) with every phase set.
        self._timeout = httpx.Timeout(timeout)

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

        # Don't send cookies manually, the client will do it for us
        if "cookie" in headers:
            del headers["cookie"]

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
                auth = HttpNtlmAuth(
                    configuration.http_credential.username,  # username should be in the form "domain\user"
                    configuration.http_credential.password
                )

        client = httpx.AsyncClient(
            auth=auth,
            headers=headers,
            cookies=configuration.cookies,
            verify=ssl_context,
            proxy=cls._fix_proxy_url(configuration.proxy),
            timeout=configuration.timeout,
            event_hooks={"request": [drop_cookies_from_request]} if configuration.drop_cookies else None,
        )

        client.max_redirects = 5
        return cls(configuration.base_request, client, configuration.timeout, scope=configuration.scope)

    @staticmethod
    def _fix_proxy_url(proxy: str) -> Optional[str]:
        """Set a proxy to use for HTTP requests."""
        if not proxy:
            return None

        url_parts = urlparse(proxy)
        protocol = url_parts.scheme.lower()

        if protocol not in ("http", "https", "socks", "socks5"):
            raise ValueError(f"Unknown proxy type: {protocol}")

        if protocol == "socks":
            protocol = "socks5"

        return urlunparse((protocol, url_parts.netloc, '/', '', '', ''))

    @property
    def timeout(self):
        return self._timeout

    @staticmethod
    def _effective_port(url: httpx.URL) -> Optional[int]:
        return url.port or DEFAULT_PORTS.get(url.scheme)

    def is_redirect_allowed(self, origin: httpx.URL, destination: httpx.URL) -> bool:
        """Tell whether a redirect from origin may be followed to destination.

        The target decides where it redirects, so following blindly would let it drive the scanner to hosts
        the operator never meant to reach (internal services, cloud metadata, a third party receiving the
        custom headers...). A redirect is followed when it stays on the host and port of the original request,
        upgrades it to HTTPS on the same host (very common) or lands within the scan scope.
        """
        if destination.host == origin.host:
            if destination.scheme == "https" or self._effective_port(destination) == self._effective_port(origin):
                return True

        return self._scope is not None and self._scope.check(str(destination))

    async def _send(
            self,
            request: httpx.Request,
            stream: bool,
            follow_redirects: bool,
            allow_offsite_redirects: bool,
    ) -> httpx.Response:
        """Send the request, following redirects ourselves so each hop goes through is_redirect_allowed.

        With allow_offsite_redirects the check is skipped: this is for URLs the operator gave explicitly
        or resources that are not the target at all (CVE data downloads...). When a hop is refused the
        redirect response itself is returned, like a scan with follow_redirects=False would get.
        """
        history = []
        response = await self._client.send(request, stream=stream, follow_redirects=False)

        while follow_redirects and response.next_request is not None:
            next_request = response.next_request

            if not allow_offsite_redirects and not self.is_redirect_allowed(request.url, next_request.url):
                if next_request.url.host not in self._refused_redirect_hosts:
                    self._refused_redirect_hosts.add(next_request.url.host)
                    # log_orange formats with str.format, not with %
                    log_orange(
                        "[!] Not following the redirect from {} to {}: outside of the target and the scan scope",
                        request.url,
                        next_request.url
                    )
                else:
                    logging.debug("Not following the redirect from %s to %s", request.url, next_request.url)
                break

            if len(history) >= self._client.max_redirects:
                raise httpx.TooManyRedirects("Exceeded maximum allowed redirects.", request=next_request)

            await response.aread()
            history.append(response)
            response = await self._client.send(next_request, stream=stream, follow_redirects=False)

        response.history = history
        return response

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
            allow_offsite_redirects: bool = False,
    ) -> Response:
        """Fetch the given url, returns a Response object on success, None otherwise.
        If None is returned, the error code can be obtained using the error_code property.

        @param resource: URL to get.
        @type resource: web.Request
        @param follow_redirects: If set to True, responses with a 3XX code and a Location header will be followed
            as long as they stay on the same host or within the scan scope (see is_redirect_allowed).
        @type follow_redirects: bool
        @param headers: Dictionary of additional headers to send with the request.
        @type headers: dict
        @type stream: bool
        @type timeout: float
        @param allow_offsite_redirects: Follow redirects wherever they go. Only for URLs chosen by the operator
            or resources that are not the scanned target.
        @type allow_offsite_redirects: bool
        @rtype: Response
        """
        final_headers = self._client.headers.copy()
        request_specific_headers = resource.headers.copy()
        if "cookie" in request_specific_headers:
            del request_specific_headers["cookie"]
        final_headers.update(request_specific_headers)

        if headers:
            final_headers.update(headers)

        timeout = self.timeout if timeout is None else httpx.Timeout(timeout)
        try:
            final_httpx_request = self._client.build_request(
                "GET", resource.url, headers=final_headers, timeout=timeout
            )
        except UnicodeEncodeError as exc:
            raise httpx.InvalidURL(f"Request contains non-encodable characters: {exc}") from exc
        resource.set_sent_headers(final_httpx_request.headers)

        try:
            response = await self._send(final_httpx_request, stream, follow_redirects, allow_offsite_redirects)
        except httpx.TransportError as exception:
            if "Read timed out" in str(exception):
                raise httpx.ReadTimeout("Request time out", request=final_httpx_request)

            raise exception
        except ssl.SSLError as exception:
            raise httpx.ConnectError(str(exception), request=final_httpx_request) from exception
        except httpx.RequestError:
            raise
        except Exception as exception:
            raise httpx.ConnectError(repr(exception), request=final_httpx_request) from exception

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
            allow_offsite_redirects: bool = False,
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
        form_headers = self._client.headers.copy()
        request_specific_headers = form.headers.copy()
        if "cookie" in request_specific_headers:
            del request_specific_headers["cookie"]
        form_headers.update(request_specific_headers)

        if form.enctype and not form.is_multipart:
            form_headers.setdefault("Content-Type", form.enctype)

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

        try:
            final_httpx_request = self._client.build_request(
                method,
                form.path,
                params=form.get_params,
                data=post_params,  # httpx expects a dict, hope to see more types soon
                content=content,
                files=file_params,
                headers=form_headers,
                timeout=self.timeout if timeout is None else httpx.Timeout(timeout)
            )
        except UnicodeEncodeError as exc:
            raise httpx.InvalidURL(f"Request contains non-encodable characters: {exc}") from exc
        form.set_sent_headers(final_httpx_request.headers)

        try:
            response = await self._send(final_httpx_request, stream, follow_redirects, allow_offsite_redirects)
        except httpx.TransportError as exception:
            if "Read timed out" in str(exception):
                raise httpx.ReadTimeout("Request time out", request=final_httpx_request)

            raise exception
        except ssl.SSLError as exception:
            raise httpx.ConnectError(str(exception), request=final_httpx_request) from exception
        except httpx.RequestError:
            raise
        except Exception as exception:
            raise httpx.ConnectError(repr(exception), request=final_httpx_request) from exception

        return Response(response)

    async def async_send(
            self,
            request: web.Request,
            headers: dict = None,
            follow_redirects: bool = False,
            stream: bool = False,
            timeout: float = None,
            allow_offsite_redirects: bool = False,
    ) -> Response:
        if request.method == "GET":
            return await self.async_get(
                request,
                headers=headers,
                follow_redirects=follow_redirects,
                stream=stream,
                timeout=timeout,
                allow_offsite_redirects=allow_offsite_redirects,
            )

        return await self.async_request(
            request.method,
            request,
            headers=headers,
            follow_redirects=follow_redirects,
            stream=stream,
            timeout=timeout,
            allow_offsite_redirects=allow_offsite_redirects,
        )

    async def close(self):
        await self._client.aclose()
