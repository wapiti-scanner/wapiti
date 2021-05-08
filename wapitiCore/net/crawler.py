#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti.sourceforge.io)
# Copyright (C) 2006-2021 Nicolas SURRIBAS
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
from random import choice
from string import ascii_letters
from enum import Enum
from urllib.parse import urlparse, urlunparse
import warnings
from collections import deque, defaultdict
import pickle
import math
import functools
from time import sleep
from typing import Tuple, List
import asyncio
from os import cpu_count

# Third-parties
import httpx
from httpx_socks import AsyncProxyTransport
from tld import get_fld
from tld.exceptions import TldDomainNotFound

# Internal libraries
from wapitiCore.language.language import _
from wapitiCore.net import web
from wapitiCore.net import swf
from wapitiCore.net import lamejs
from wapitiCore.net.page import Page

warnings.filterwarnings(action='ignore', category=UserWarning, module='bs4')


class Scope(Enum):
    FOLDER = 1
    PAGE = 2
    URL = 3
    DOMAIN = 4
    PUNK = 5


MIME_TEXT_TYPES = ('text/', 'application/xml')
# Limit page size to 2MB
MAX_PAGE_SIZE = 2097152

COMMON_PAGE_EXTENSIONS = {
    'php', 'html', 'htm', 'xml', 'xhtml', 'xht', 'xhtm', 'cgi',
    'asp', 'aspx', 'php3', 'php4', 'php5', 'txt', 'shtm',
    'shtml', 'phtm', 'phtml', 'jhtml', 'pl', 'jsp', 'cfm', 'cfml'
}

EXCLUDED_MEDIA_EXTENSIONS = (
    # File extensions we don't want to deal with. Js and SWF files won't be in this list.
    '.7z', '.aac', '.aiff', '.au', '.avi', '.bin', '.bmp', '.cab', '.dll', '.dmp', '.ear', '.exe', '.flv', '.gif',
    '.gz', '.ico', '.image', '.iso', '.jar', '.jpeg', '.jpg', '.mkv', '.mov', '.mp3', '.mp4', '.mpeg', '.mpg', '.pdf',
    '.png', '.ps', '.rar', '.scm', '.so', '.tar', '.tif', '.war', '.wav', '.wmv', '.zip'
)

BAD_URL_REGEX = re.compile(r"https?:/[^/]+")


def wildcard_translate(pattern):
    """Translate a wildcard PATTERN to a regular expression object.

    This is largely inspired by fnmatch.translate.
    """

    i, length = 0, len(pattern)
    res = ''
    while i < length:
        char = pattern[i]
        i += 1
        if char == '*':
            res += r'.*'
        else:
            res += re.escape(char)
    return re.compile(res + r'\Z(?ms)')


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
                    sleep(delay)

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
            self, base_url: str, timeout: float = 10.0, secure: bool = False, compression: bool = True):
        self._timeout = timeout
        self.stream = False
        self._scope = Scope.FOLDER
        self._base = web.Request(base_url)
        self.auth_url = self._base.url
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

        if protocol not in ("http", "https", "socks"):
            raise ValueError("Unknown proxy type: {}".format(protocol))

        if protocol == "socks":
            self._transport = AsyncProxyTransport.from_url(urlunparse(("socks5", url_parts.netloc, '/', '', '', '')))
        else:
            proxy_url = urlunparse((url_parts.scheme, url_parts.netloc, '/', '', '', ''))
            self._proxies = {"http://": proxy_url, "https://": proxy_url}

    @property
    def client(self):
        # Construct or reconstruct an AsyncClient instance using parameters
        if self._client is None:
            self._client = httpx.AsyncClient(
                auth=self._auth,
                headers=self._headers,
                cookies=self._cookies,
                verify=self._secure,
                proxies=self._proxies,
                timeout=self._timeout,
                event_hooks={"request": [drop_cookies_from_request]} if self._drop_cookies else None,
                transport=self._transport,
                limits=httpx.Limits(max_keepalive_connections=None, max_connections=None)
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
            raise ValueError("Invalid scope value {}".format(value))
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

    async def async_try_login(self, auth_url: str):
        """Try to authenticate with the provided url and credentials."""
        if len(self._auth_credentials) != 2:
            print(_("Login failed") + " : " + _("Invalid credentials format"))
            return

        username, password = self._auth_credentials

        # Fetch the login page and try to extract the login form
        try:
            page = await self.async_get(web.Request(auth_url), follow_redirects=True)

            login_form, username_field_idx, password_field_idx = page.find_login_form()
            if login_form:
                post_params = login_form.post_params
                get_params = login_form.get_params

                if login_form.method == "POST":
                    post_params[username_field_idx][1] = username
                    post_params[password_field_idx][1] = password
                else:
                    get_params[username_field_idx][1] = username
                    get_params[password_field_idx][1] = password

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
                if login_response.soup.find_all(text=re.compile(r'(?i)((log|sign)\s?out|disconnect|déconnexion)')):
                    self.is_logged_in = True
                    print(_("Login success"))

                else:
                    print(_("Login failed") + " : " + _("Credentials might be invalid"))
            else:
                print(_("Login failed") + " : " + _("No login form detected"))

        except ConnectionError:
            print(_("[!] Connection error with URL"), auth_url)
        except httpx.RequestError as error:
            print(_("[!] {} with url {}").format(error.__class__.__name__, auth_url))

    @retry(delay=1, times=3)
    async def async_get(self, resource: web.Request, follow_redirects: bool = False, headers: dict = None) -> Page:
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
        request = self.client.build_request("GET", resource.url, headers=headers)
        try:
            response = await self.client.send(
                request, stream=self.stream, allow_redirects=follow_redirects, timeout=self._timeout
            )
        except httpx.TransportError as exception:
            if "Read timed out" in str(exception):
                raise httpx.ReadTimeout("Request time out", request=None)

            raise exception

        return Page(response)

    @retry(delay=1, times=3)
    async def async_post(self, form: web.Request, follow_redirects: bool = False, headers: dict = None) -> Page:
        """Submit the given form, returns a Page on success, None otherwise.

        @type form: web.Request
        @type follow_redirects: bool
        @type headers: dict
        @rtype: Page
        """
        form_headers = {}
        if not form.is_multipart:
            form_headers = {"Content-Type": form.enctype}

        if isinstance(headers, dict) and len(headers):
            form_headers.update(headers)

        if form.referer:
            form_headers["referer"] = form.referer

        if form.is_multipart:
            file_params = form.post_params + form.file_params
            post_params = []
        elif "urlencoded" in form.enctype:
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
            headers=form_headers
        )
        try:
            response = await self.client.send(
                request, stream=self.stream, allow_redirects=follow_redirects, timeout=self._timeout
            )
        except httpx.TransportError as exception:
            if "Read timed out" in str(exception):
                raise httpx.ReadTimeout("Request time out", request=None)

            raise exception

        return Page(response)

    @retry(delay=1, times=3)
    async def async_request(
            self, method: str, form: web.Request, follow_redirects: bool = False, headers: dict = None) -> Page:
        """Submit the given form, returns a Page on success, None otherwise.

        @type method: str
        @type form: web.Request
        @type follow_redirects: bool
        @type headers: dict
        @rtype: Page
        """
        form_headers = {}
        if isinstance(headers, dict) and len(headers):
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
        )
        try:
            response = await self.client.send(
                request, stream=self.stream, allow_redirects=follow_redirects, timeout=self._timeout
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
        resource.set_headers(page.headers)
        return page

    async def close(self):
        await self.client.aclose()


class Explorer:
    def __init__(self, crawler_instance: AsyncCrawler, stop_event: asyncio.Event, parallelism: int = 8):
        self._crawler = crawler_instance
        self._max_depth = 20
        self._max_page_size = MAX_PAGE_SIZE
        self._log = True
        self._bad_params = set()
        self._max_per_depth = 0
        self._max_files_per_dir = 0
        self._qs_limit = 0
        self._hostnames = set()
        self._regexes = []
        self._processed_requests = []

        # Locking required for writing to the following structures
        self._file_counts = defaultdict(int)
        self._pattern_counts = defaultdict(int)
        self._custom_404_codes = {}
        # Corresponding lock
        self._shared_lock = asyncio.Lock()

        # Semaphore used to limit parallelism
        self._sem = asyncio.Semaphore(parallelism)
        # Event to stop processing tasks
        self._stopped = stop_event

        # CPU count + 4 is default concurrent tasks for CPython ThreadPoolExecutor with a high limit set at 32
        self._max_tasks = min(parallelism, 32, (cpu_count() or 1) + 4)
        self._max_tasks += round(self._max_tasks / 2)

    @property
    def max_depth(self) -> int:
        return self._max_depth

    @max_depth.setter
    def max_depth(self, value: int):
        self._max_depth = value

    @property
    def max_page_size(self) -> int:
        return self._max_page_size

    @max_page_size.setter
    def max_page_size(self, value: int):
        self._max_page_size = value

    @property
    def verbose(self) -> bool:
        return self._log

    @verbose.setter
    def verbose(self, value: bool):
        self._log = value

    @property
    def forbidden_parameters(self) -> set:
        return self._bad_params

    @forbidden_parameters.setter
    def forbidden_parameters(self, value: set):
        self._bad_params = value

    @property
    def max_requests_per_depth(self) -> int:
        return self._max_per_depth

    @max_requests_per_depth.setter
    def max_requests_per_depth(self, value: int):
        self._max_per_depth = value

    @property
    def max_files_per_dir(self) -> int:
        return self._max_files_per_dir

    @max_files_per_dir.setter
    def max_files_per_dir(self, value: int):
        self._max_files_per_dir = value

    @property
    def qs_limit(self) -> int:
        return self._qs_limit

    @qs_limit.setter
    def qs_limit(self, value: int):
        self._qs_limit = value

    def save_state(self, pickle_file: str):
        with open(pickle_file, "wb") as file_data:
            pickle.dump(
                {
                    "custom_404_codes": self._custom_404_codes,
                    "file_counts": self._file_counts,
                    "pattern_counts": self._pattern_counts,
                    "hostnames": self._hostnames
                },
                file_data,
                pickle.HIGHEST_PROTOCOL
            )

    def load_saved_state(self, pickle_file: str):
        try:
            with open(pickle_file, "rb") as file_data:
                data = pickle.load(file_data)
                self._custom_404_codes = data["custom_404_codes"]
                self._file_counts = data["file_counts"]
                self._pattern_counts = data["pattern_counts"]
                self._hostnames = data["hostnames"]
        except FileNotFoundError:
            pass

    def is_forbidden(self, candidate_url: str):
        return any(regex.match(candidate_url) for regex in self._regexes)

    def extract_links(self, page, request) -> List:
        swf_links = []
        js_links = []
        allowed_links = []

        new_requests = []

        if "application/x-shockwave-flash" in page.type or request.file_ext == "swf":
            try:
                swf_links = swf.extract_links_from_swf(page.bytes)
            except Exception:
                pass
        elif "/x-javascript" in page.type or "/x-js" in page.type or "/javascript" in page.type:
            js_links = lamejs.LameJs(page.content).get_links()
        elif page.type.startswith(MIME_TEXT_TYPES):
            allowed_links.extend(filter(self._crawler.is_in_scope, page.links))
            allowed_links.extend(filter(self._crawler.is_in_scope, page.js_redirections + page.html_redirections))

            for extra_url in filter(self._crawler.is_in_scope, page.extra_urls):
                parts = urlparse(extra_url)
                # There are often css and js URLs with useless parameters like version or random number
                # used to prevent caching in browser. So let's exclude those extensions
                if parts.path.endswith(".css"):
                    continue

                if parts.path.endswith(".js") and parts.query:
                    # For JS script, allow to process them but remove parameters
                    allowed_links.append(extra_url.split("?")[0])
                    continue

                allowed_links.append(extra_url)

            for form in page.iter_forms():
                # TODO: apply bad_params filtering in form URLs
                if self._crawler.is_in_scope(form):
                    if form.hostname not in self._hostnames:
                        form.link_depth = 0
                    else:
                        form.link_depth = request.link_depth + 1

                    new_requests.append(form)

        for url in swf_links + js_links:
            if url:
                url = page.make_absolute(url)
                if url and self._crawler.is_in_scope(url):
                    allowed_links.append(url)

        for new_url in allowed_links:
            if "?" in new_url:
                path_only = new_url.split("?")[0]
                if path_only not in allowed_links and self._crawler.is_in_scope(path_only):
                    allowed_links.append(path_only)

        for new_url in set(allowed_links):
            if new_url == "":
                continue

            if self.is_forbidden(new_url):
                continue

            if "?" in new_url:
                path, query_string = new_url.split("?", 1)
                # TODO: encoding parameter ?
                get_params = [
                    list(t) for t in filter(
                        lambda param_tuple: param_tuple[0] not in self._bad_params,
                        web.parse_qsl(query_string)
                    )
                ]
            elif new_url.endswith(EXCLUDED_MEDIA_EXTENSIONS):
                # exclude static media files
                continue
            else:
                path = new_url
                get_params = []

            if page.is_directory_redirection and new_url == page.redirection_url:
                depth = request.link_depth
            else:
                depth = request.link_depth + 1

            new_requests.append(web.Request(path, get_params=get_params, link_depth=depth))

        return new_requests

    async def async_analyze(self, request) -> Tuple[bool, List]:
        async with self._sem:
            self._processed_requests.append(request)  # thread safe

            if self._log:
                print("[+] {0}".format(request))

            dir_name = request.dir_name
            async with self._shared_lock:
                # lock to prevent launching duplicates requests that would otherwise waste time
                if dir_name not in self._custom_404_codes:
                    invalid_page = "zqxj{0}.html".format("".join([choice(ascii_letters) for __ in range(10)]))
                    invalid_resource = web.Request(dir_name + invalid_page)
                    try:
                        page = await self._crawler.async_get(invalid_resource)
                        self._custom_404_codes[dir_name] = page.status
                    except httpx.RequestError:
                        pass

            self._hostnames.add(request.hostname)

            resource_url = request.url

            try:
                page = await self._crawler.async_send(request)
            except (TypeError, UnicodeDecodeError) as exception:
                print("{} with url {}".format(exception, resource_url))  # debug
                return False, []
            # except SSLError:
            #     print(_("[!] SSL/TLS error occurred with URL"), resource_url)
            #     return False, []
            # TODO: what to do of connection errors ? sleep a while before retrying ?
            except ConnectionError:
                print(_("[!] Connection error with URL"), resource_url)
                return False, []
            except httpx.RequestError as error:
                print(_("[!] {} with url {}").format(error.__class__.__name__, resource_url))
                return False, []

            if self._max_files_per_dir:
                async with self._shared_lock:
                    self._file_counts[dir_name] += 1

            if self._qs_limit and request.parameters_count:
                async with self._shared_lock:
                    self._pattern_counts[request.pattern] += 1

            if request.link_depth == self._max_depth:
                # We are at the edge of the depth so next links will have depth + 1 so to need to parse the page.
                return True, []

            # Above this line we need the content of the page. As we are in stream mode we must force reading the body.
            await page.read()

            # Sur les ressources statiques le content-length est généralement indiqué
            if self._max_page_size > 0:
                if page.raw_size > self._max_page_size:
                    page.clean()
                    return False, []

            resources = self.extract_links(page, request)
            # TODO: there's more situations where we would not want to attack the resource... must check this
            if page.is_directory_redirection:
                return False, resources

            return True, resources

    async def async_explore(
            self,
            to_explore: deque,
            excluded_urls: list = None
    ):
        """Explore a single TLD or the whole Web starting with an URL

        @param to_explore: A list of URL to scan the scan with.
        @type to_explore: list
        @param excluded_urls: A list of URLs to skip. Request objects or strings which may contain wildcards.
        @type excluded_urls: list

        @rtype: generator
        """
        if isinstance(excluded_urls, list):
            while True:
                try:
                    bad_request = excluded_urls.pop()
                except IndexError:
                    break
                else:
                    if isinstance(bad_request, str):
                        self._regexes.append(wildcard_translate(bad_request))
                    elif isinstance(bad_request, web.Request):
                        self._processed_requests.append(bad_request)

        self._crawler.stream = True

        if self._max_depth < 0:
            raise StopIteration

        task_to_request = {}
        while True:
            while to_explore:
                # Concurrent tasks are limited through the use of the semaphore BUT we don't want the to_explore
                # queue to be empty everytime (as we may need to extract remaining URLs) and overload the event loop
                # with pending tasks.
                # There may be more suitable way to do this though.
                if len(task_to_request) > self._max_tasks:
                    break

                if self._stopped.is_set():
                    break

                request = to_explore.popleft()
                if not isinstance(request, web.Request):
                    # We treat start_urls as if they are all valid URLs (ie in scope)
                    request = web.Request(request, link_depth=0)

                if request in self._processed_requests:
                    continue

                resource_url = request.url

                if request.link_depth > self._max_depth:
                    continue

                dir_name = request.dir_name
                if self._max_files_per_dir and self._file_counts[dir_name] >= self._max_files_per_dir:
                    continue

                # Won't enter if qs_limit is 0 (aka insane mode)
                if self._qs_limit:
                    if request.parameters_count:
                        try:
                            if self._pattern_counts[
                                request.pattern
                            ] >= 220 / (math.exp(request.parameters_count * self._qs_limit) ** 2):
                                continue
                        except OverflowError:
                            # Oh boy... that's not good to try to attack a form with more than 600 input fields
                            # but I guess insane mode can do it as it is insane
                            continue

                if self.is_forbidden(resource_url):
                    continue

                task = asyncio.create_task(self.async_analyze(request))
                task_to_request[task] = request

            if task_to_request:
                done, __ = await asyncio.wait(
                    task_to_request,
                    timeout=0.25,
                    return_when=asyncio.FIRST_COMPLETED
                )
            else:
                done = []

            # process any completed task
            for task in done:
                request = task_to_request[task]
                try:
                    success, resources = await task
                except Exception as exc:
                    print('%r generated an exception: %s' % (request, exc))
                else:
                    if success:
                        yield request

                    accepted_urls = 0
                    for unfiltered_request in resources:
                        if BAD_URL_REGEX.search(unfiltered_request.file_path):
                            # Malformed link due to HTML issues
                            continue

                        if not self._crawler.is_in_scope(unfiltered_request):
                            continue

                        if unfiltered_request.hostname not in self._hostnames:
                            unfiltered_request.link_depth = 0

                        if unfiltered_request not in self._processed_requests and unfiltered_request not in to_explore:
                            to_explore.append(unfiltered_request)
                            accepted_urls += 1

                        # TODO: fix this, it doesn't looks valid
                        # if self._max_per_depth and accepted_urls >= self._max_per_depth:
                        #     break

                # remove the now completed task
                del task_to_request[task]

            if not task_to_request and (self._stopped.is_set() or not to_explore):
                break

        self._crawler.stream = False
