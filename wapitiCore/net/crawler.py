#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2006-2022 Nicolas SURRIBAS
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
from typing import Tuple, List, Dict
import asyncio
import ssl

# Third-parties
import httpx

# Internal libraries
from wapitiCore.language.language import _
from wapitiCore.net import web
from wapitiCore.net.crawler_configuration import CrawlerConfiguration

from wapitiCore.net.response import Response
from wapitiCore.net.html import Html
from wapitiCore.main.log import logging

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
            form_credentials: Tuple[str, str] = None,
    ):
        self._base_request = base_request
        self._client = client
        self._timeout = timeout
        self._auth_credentials = form_credentials

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
        form_credentials = tuple()
        if len(configuration.auth_credentials) == 2:
            username, password = configuration.auth_credentials

            if configuration.auth_method == "basic":
                auth = httpx.BasicAuth(username, password)
            elif configuration.auth_method == "digest":
                auth = httpx.DigestAuth(username, password)
            elif configuration.auth_method == "ntlm":
                # https://github.com/ulodciv/httpx-ntlm
                from httpx_ntlm import HttpNtlmAuth
                auth = HttpNtlmAuth(username, password)  # username in the form domain\user
            elif configuration.auth_method == "post":
                form_credentials = username, password

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
        return cls(configuration.base_request, client, configuration.timeout, form_credentials)

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
    def session_cookies(self):
        """Getter for session cookies (returns a Cookies object)"""
        return self._client.cookies

    # Should be put outside of crawler now that the "scope" was moved
    async def async_try_login(
            self,
            auth_credentials: Tuple[str, str],
            auth_url: str,
            auth_type: str
    ) -> Tuple[bool, dict, List[str]]:
        """
        Try to authenticate with the provided url and credentials.
        Returns if the authentication has been successful, the used form variables and the disconnect urls.
        """
        if len(auth_credentials) != 2:
            logging.error(_("Login failed") + " : " + _("Invalid credentials format"))
            return False, {}, []

        username, password = auth_credentials

        if auth_type == "post" and auth_url:
            return await self._async_try_login_post(username, password, auth_url)
        return await self._async_try_login_basic_digest_ntlm(auth_url)

    async def _async_try_login_basic_digest_ntlm(self, auth_url: str) -> Tuple[bool, dict, List[str]]:
        response = await self.async_get(web.Request(auth_url))

        if response.status in (401, 403, 404):
            return False, {}, []
        return True, {}, []

    async def _async_try_login_post(self, username: str, password: str, auth_url: str) -> Tuple[bool, dict, List[str]]:
        # Fetch the login page and try to extract the login form
        try:
            response: Response = await self.async_get(web.Request(auth_url), follow_redirects=True)
            form = {}
            disconnect_urls = []

            page = Html(response.content, auth_url)

            login_form, username_field_idx, password_field_idx = page.find_login_form()
            if login_form:
                post_params = login_form.post_params
                get_params = login_form.get_params

                if login_form.method == "POST":
                    post_params[username_field_idx][1] = username
                    post_params[password_field_idx][1] = password
                    form["login_field"] = post_params[username_field_idx][0]
                    form["password_field"] = post_params[password_field_idx][0]
                else:
                    get_params[username_field_idx][1] = username
                    get_params[password_field_idx][1] = password
                    form["login_field"] = get_params[username_field_idx][0]
                    form["password_field"] = get_params[password_field_idx][0]

                login_request = web.Request(
                    path=login_form.url,
                    method=login_form.method,
                    post_params=post_params,
                    get_params=get_params,
                    referer=login_form.referer,
                    link_depth=login_form.link_depth
                )

                login_response = await self.async_send(
                    login_request,
                    follow_redirects=True
                )

                html = Html(login_response.content, login_response.url)

                # ensure logged in
                self.is_logged_in = html.is_logged_in()
                if self.is_logged_in:
                    logging.success(_("Login success"))
                    disconnect_urls = html.extract_disconnect_urls()
                else:
                    logging.warning(_("Login failed") + " : " + _("Credentials might be invalid"))
            else:
                logging.warning(_("Login failed") + " : " + _("No login form detected"))
            return self.is_logged_in, form, disconnect_urls

        except ConnectionError:
            logging.error(_("[!] Connection error with URL"), auth_url)
            return False, {}, []
        except httpx.RequestError as error:
            logging.error(_("[!] {} with URL {}").format(error.__class__.__name__, auth_url))
            return False, {}, []

    @retry(delay=1, times=3)
    async def async_get(
            self,
            resource: web.Request,
            follow_redirects: bool = False,
            headers: dict = None,
            stream: bool = False
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
        @rtype: Response
        """
        request = self._client.build_request("GET", resource.url, headers=headers, timeout=self.timeout)
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
    async def async_post(
            self,
            form: web.Request,
            follow_redirects: bool = False,
            headers: dict = None,
            stream: bool = False
    ) -> Response:
        """Submit the given form, returns a Response on success, None otherwise.

        @type form: web.Request
        @type follow_redirects: bool
        @type headers: dict
        @type stream: bool
        @rtype: Response
        """
        form_headers = {}
        if not form.is_multipart:
            form_headers = {"Content-Type": form.enctype}

        if isinstance(headers, dict) and headers:
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
            "POST",
            form.path,
            params=form.get_params,
            data=post_params,  # httpx expects a dict, hope to see more types soon
            content=content,
            files=file_params or None,
            headers=form_headers,
            timeout=self.timeout
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

    @retry(delay=1, times=3)
    async def async_request(
            self,
            method: str,
            form: web.Request,
            follow_redirects: bool = False,
            headers: dict = None,
            stream: bool = False
    ) -> Response:
        """Submit the given form, returns a Response on success, None otherwise.

        @type method: str
        @type form: web.Request
        @type follow_redirects: bool
        @type headers: dict
        @type stream: bool
        @rtype: Response
        """
        form_headers = {}
        if isinstance(headers, dict) and headers:
            form_headers.update(headers)

        if form.referer:
            form_headers["referer"] = form.referer

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
            form.url,
            data=post_params,
            content=content,
            files=form.file_params or None,
            headers=form_headers,
            timeout=self.timeout
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
            stream: bool = False
    ) -> Response:
        if request.method == "GET":
            response = await self.async_get(request, headers=headers, follow_redirects=follow_redirects, stream=stream)
        elif request.method == "POST":
            response = await self.async_post(
                request,
                headers=headers,
                follow_redirects=follow_redirects,
                stream=stream
            )
        else:
            response = await self.async_request(
                request.method, request, headers=headers, follow_redirects=follow_redirects, stream=stream
            )

        request.set_cookies(self._client.cookies)
        request.set_headers(response.sent_headers)
        return response

    async def close(self):
        await self._client.aclose()
