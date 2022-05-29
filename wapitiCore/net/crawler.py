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
import re
from enum import Enum
from urllib.parse import urlparse, urlunparse
import warnings
import functools
from typing import Tuple, List
import asyncio
import ssl

# Third-parties
import httpx
from tld import get_fld
from tld.exceptions import TldDomainNotFound

# Internal libraries
from wapitiCore.language.language import _
from wapitiCore.net import web

from wapitiCore.net.page import Page
from wapitiCore.main.log import logging

warnings.filterwarnings(action='ignore', category=UserWarning, module='bs4')


class Scope(Enum):
    FOLDER = 1
    PAGE = 2
    URL = 3
    DOMAIN = 4
    PUNK = 5


DISCONNECT_REGEX = r'(?i)((log|sign)\s?(out|off)|disconnect|déconnexion)'


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
            self, base_request: web.Request, timeout: float = 10.0, secure: bool = False, compression: bool = True):
        self._timeout = timeout
        self.stream = False
        self._scope = Scope.FOLDER
        self._base: web.Request = base_request
        self.auth_url: str = self._base.url
        self.is_logged_in = False
        self._user_agent = "Mozilla/5.0 (Windows NT 6.1; rv:45.0) Gecko/20100101 Firefox/45.0"
        self._headers = {
            "User-Agent": self._user_agent,
            "Accept-Language": "en-US",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
        }

        if not compression:
            self._client.headers["Accept-Encoding"] = "identity"

        self._secure = secure
        self._proxies = None
        self._transport = None
        self._drop_cookies = False
        self._cookies = None

        self._client = None
        self._auth_credentials = {}
        self._auth_method = "basic"
        self._auth = None

    def set_proxy(self, proxy: str):
        """Set a proxy to use for HTTP requests."""
        self._client = None
        self._transport = None
        self._proxies = None

        url_parts = urlparse(proxy)
        protocol = url_parts.scheme.lower()

        if protocol not in ("http", "https", "socks", "socks5"):
            raise ValueError(f"Unknown proxy type: {protocol}")

        if protocol == "socks":
            protocol = "socks5"

        self._proxies = {
            "http://": urlunparse((protocol, url_parts.netloc, '/', '', '', '')),
            "https://": urlunparse((protocol, url_parts.netloc, '/', '', '', '')),
        }

    @property
    def client(self):
        # Construct or reconstruct an AsyncClient instance using parameters
        if self._client is None:
            ssl_context = httpx.create_ssl_context()
            ssl_context.check_hostname = self._secure
            ssl_context.verify_mode = ssl.CERT_REQUIRED if self._secure else ssl.CERT_NONE

            # Allows dead protocols like SSL and TLS1
            ssl_context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED

            self._client = httpx.AsyncClient(
                auth=self._auth,
                headers=self._headers,
                cookies=self._cookies,
                verify=ssl_context,
                proxies=self._proxies,
                timeout=self._timeout,
                event_hooks={"request": [drop_cookies_from_request]} if self._drop_cookies else None,
                transport=self._transport
            )

            self._client.max_redirects = 5

        return self._client

    @property
    def secure(self):
        return self._secure

    @secure.setter
    def secure(self, value: bool):
        if value != self._secure:
            # We can't set `verify` using a setter so AsyncClient must be created again
            self._client = None
            self._secure = value

    @property
    def timeout(self):
        return self._timeout

    @timeout.setter
    def timeout(self, value: float):
        # We don't care setting it on _client because timeout is used at each get/post/send call
        self._timeout = value

    @property
    def scope(self):
        return self._scope

    @scope.setter
    def scope(self, value: int):
        if value not in Scope:
            raise ValueError(f"Invalid scope value {value}")
        self._scope = value

    def is_in_scope(self, resource):
        if self._scope == Scope.PUNK:
            # Life is short
            return True

        if isinstance(resource, web.Request):
            if self._scope == Scope.FOLDER:
                return resource.url.startswith(self._base.path)
            if self._scope == Scope.PAGE:
                return resource.path == self._base.path
            if self._scope == Scope.URL:
                return resource.url == self._base.url
            # Scope.DOMAIN
            try:
                return get_fld(resource.url) == get_fld(self._base.url)
            except TldDomainNotFound:
                return resource.hostname == self._base.hostname
        else:
            if not resource:
                return False

            if self._scope == Scope.FOLDER:
                return resource.startswith(self._base.path)
            if self._scope == Scope.PAGE:
                return resource.split("?")[0] == self._base.path
            if self._scope == Scope.URL:
                return resource == self._base.url
            # Scope.DOMAIN
            try:
                return get_fld(resource) == get_fld(self._base.url)
            except TldDomainNotFound:
                return urlparse(resource).netloc == self._base.hostname

    @property
    def user_agent(self):
        """Getter for user-agent property"""
        return self._user_agent

    @user_agent.setter
    def user_agent(self, value: str):
        """Setter for user-agent property"""
        if not isinstance(value, str):
            raise TypeError("Invalid type for User-Agent. Type str required.")

        if value != self._user_agent:
            self._headers["User-Agent"] = value
            # We can update headers on the client this way. Will instantiate _client if it doesn't exist
            self.client.headers.update(self._headers)

    def add_custom_header(self, key: str, value: str):
        """Set a HTTP header to use for every requests"""
        # We modify our own dict because if another setter rewrite the client we want to reuse the value.
        self._headers[key] = value
        # We can update headers on the client this way
        self.client.headers.update(self._headers)

    @property
    def session_cookies(self):
        """Getter for session cookies (returns a Cookies object)"""
        return self.client.cookies

    @session_cookies.setter
    def session_cookies(self, value):
        """Setter for session cookies (value may be a dict or CookieJar object)"""
        self._client = None
        self._cookies = value

    @property
    def drop_cookies(self) -> bool:
        return self._drop_cookies

    @drop_cookies.setter
    def drop_cookies(self, value: bool):
        if self._drop_cookies != value:
            # Erase current ASyncClient instance as event_hooks must be set at init
            self._client = None
            self._drop_cookies = value

    @property
    def credentials(self):
        return self._auth_credentials

    @credentials.setter
    def credentials(self, value):
        """Set credentials to use if the website require an authentication."""
        self._auth_credentials = value
        # Force reload
        self.auth_method = self._auth_method

    @property
    def auth_method(self):
        return self._auth_method

    @auth_method.setter
    def auth_method(self, value):
        """Set the authentication method to use for the requests."""
        self._auth_method = value
        if len(self._auth_credentials) == 2:
            username, password = self._auth_credentials
            self._auth = None

            if self._auth_method == "basic":
                self._auth = httpx.BasicAuth(username, password)
            elif self._auth_method == "digest":
                self._auth = httpx.DigestAuth(username, password)
            elif self._auth_method == "ntlm":
                # https://github.com/ulodciv/httpx-ntlm
                from httpx_ntlm import HttpNtlmAuth
                self._auth = HttpNtlmAuth(username, password)  # username in the form domain\user

            self.client.auth = self._auth

    async def async_try_login(self, auth_url: str, auth_type: str) -> Tuple[bool, dict, List[str]]:
        """
        Try to authenticate with the provided url and credentials.
        Returns if the the authentication has been successful, the used form variables and the disconnect urls.
        """
        if len(self._auth_credentials) != 2:
            logging.error(_("Login failed") + " : " + _("Invalid credentials format"))
            return False, {}, []

        username, password = self._auth_credentials

        if auth_type == "post":
            return await self._async_try_login_post(username, password, auth_url)
        return await self._async_try_login_basic_digest_ntlm(auth_url)

    async def _async_try_login_basic_digest_ntlm(self, auth_url: str) -> Tuple[bool, dict, List[str]]:
        page = await self.async_get(web.Request(auth_url))

        if page.status in (401, 403, 404):
            return False, {}, []
        return True, {}, []

    def _extract_disconnect_urls(self, page: Page) -> List[str]:
        """
        Extract all the disconnect urls on the given page and returns them.
        """
        disconnect_urls = []
        for link in page.links:
            if self.is_in_scope(link) is False:
                continue

            if re.search(DISCONNECT_REGEX, link) is not None:
                disconnect_urls.append(page.make_absolute(link))
        return disconnect_urls

    async def _async_try_login_post(self, username: str, password: str, auth_url: str) -> Tuple[bool, dict, List[str]]:
        # Fetch the login page and try to extract the login form
        try:
            page = await self.async_get(web.Request(auth_url), follow_redirects=True)
            form = {}
            disconnect_urls = []

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

                # ensure logged in
                if login_response.soup.find_all(
                        text=re.compile(DISCONNECT_REGEX)
                ):
                    self.is_logged_in = True
                    logging.success(_("Login success"))
                    disconnect_urls = self._extract_disconnect_urls(login_response)
                else:
                    logging.warning(_("Login failed") + " : " + _("Credentials might be invalid"))
            else:
                logging.warning(_("Login failed") + " : " + _("No login form detected"))
            return self.is_logged_in, form, disconnect_urls

        except ConnectionError:
            logging.error(_("[!] Connection error with URL"), auth_url)
            return False, {}, []
        except httpx.RequestError as error:
            logging.error(_("[!] {} with url {}").format(error.__class__.__name__, auth_url))
            return False, {}, []

    @retry(delay=1, times=3)
    async def async_get(
            self,
            resource: web.Request,
            follow_redirects: bool = False,
            headers: dict = None
    ) -> Page:
        """Fetch the given url, returns a Page object on success, None otherwise.
        If None is returned, the error code can be obtained using the error_code property.

        @param resource: URL to get.
        @type resource: web.Request
        @param follow_redirects: If set to True, responses with a 3XX code and a Location header will be followed.
        @type follow_redirects: bool
        @param headers: Dictionary of additional headers to send with the request.
        @type headers: dict
        @rtype: Page
        """
        request = self.client.build_request("GET", resource.url, headers=headers, timeout=self._timeout)
        try:
            response = await self.client.send(
                request, stream=self.stream, follow_redirects=follow_redirects
            )
        except httpx.TransportError as exception:
            if "Read timed out" in str(exception):
                raise httpx.ReadTimeout("Request time out", request=None)

            raise exception

        return Page(response)

    @retry(delay=1, times=3)
    async def async_post(
            self,
            form: web.Request,
            follow_redirects: bool = False,
            headers: dict = None
    ) -> Page:
        """Submit the given form, returns a Page on success, None otherwise.

        @type form: web.Request
        @type follow_redirects: bool
        @type headers: dict
        @rtype: Page
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

        request = self.client.build_request(
            "POST",
            form.path,
            params=form.get_params,
            data=post_params,  # httpx expects a dict, hope to see more types soon
            content=content,
            files=file_params or None,
            headers=form_headers,
            timeout=self._timeout
        )
        try:
            response = await self.client.send(
                request, stream=self.stream, follow_redirects=follow_redirects
            )
        except httpx.TransportError as exception:
            if "Read timed out" in str(exception):
                raise httpx.ReadTimeout("Request time out", request=None)

            raise exception

        return Page(response)

    @retry(delay=1, times=3)
    async def async_request(
            self,
            method: str,
            form: web.Request,
            follow_redirects: bool = False,
            headers: dict = None
    ) -> Page:
        """Submit the given form, returns a Page on success, None otherwise.

        @type method: str
        @type form: web.Request
        @type follow_redirects: bool
        @type headers: dict
        @rtype: Page
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

        request = self.client.build_request(
            method,
            form.url,
            data=post_params,
            content=content,
            files=form.file_params or None,
            headers=form_headers,
            timeout=self._timeout
        )
        try:
            response = await self.client.send(
                request, stream=self.stream, follow_redirects=follow_redirects
            )
        except httpx.TransportError as exception:
            if "Read timed out" in str(exception):
                raise httpx.ReadTimeout("Request time out", request=None)

            raise exception

        return Page(response)

    async def async_send(self, resource: web.Request, headers: dict = None, follow_redirects: bool = False) -> Page:
        if resource.method == "GET":
            page = await self.async_get(resource, headers=headers, follow_redirects=follow_redirects)
        elif resource.method == "POST":
            page = await self.async_post(resource, headers=headers, follow_redirects=follow_redirects)
        else:
            page = await self.async_request(
                resource.method, resource, headers=headers, follow_redirects=follow_redirects
            )

        resource.status = page.status
        resource.set_cookies(self._cookies)
        resource.set_headers(page.headers)
        resource.set_sent_headers(page.sent_headers)
        return page

    async def close(self):
        await self.client.aclose()
