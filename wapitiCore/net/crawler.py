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
from http import cookiejar
from typing import Tuple, List
import asyncio

# Third-parties
import requests
from requests.packages.urllib3 import disable_warnings
from requests.packages.urllib3.exceptions import ReadTimeoutError
from requests.exceptions import ConnectionError, RequestException, ReadTimeout, SSLError
from tld import get_fld
from tld.exceptions import TldDomainNotFound

# Internal libraries
from wapitiCore.language.language import _
from wapitiCore.net import web
from wapitiCore.net import swf
from wapitiCore.net import lamejs
from wapitiCore.net.page import Page

disable_warnings()
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
        def inner_wrapper(*args, **kwargs):
            final_excep = None
            for counter in range(times):
                if counter > 0:
                    sleep(delay)

                try:
                    value = function(*args, **kwargs)
                    return value
                except ConnectionError as exception:
                    if hasattr(exception.args[0], "reason") and isinstance(exception.args[0].reason, ReadTimeoutError):
                        final_excep = ReadTimeout(exception.args[0])
                    else:
                        raise exception
                except ReadTimeout as exception:
                    final_excep = exception

            if final_excep is not None:
                raise final_excep

        return inner_wrapper

    return outer_wrapper


class BlockAll(cookiejar.CookiePolicy):
    return_ok = set_ok = domain_return_ok = path_return_ok = lambda self, *args, **kwargs: False
    netscape = True
    rfc2965 = hide_cookie2 = False


class Crawler:
    SUCCESS = 0
    TIMEOUT = 1
    HTTP_ERROR = 2
    INVALID_URL = 3
    CONNECT_ERROR = 4
    SSL_ERROR = 5
    UNKNOWN_ERROR = 6

    def __init__(
            self, base_url: str, timeout: float = 10.0, secure: bool = False, compression: bool = True,
            proxies: dict = None, user_agent: str = None):
        self._timeout = timeout
        self._session = requests.Session()
        if user_agent:
            self._session.headers["User-Agent"] = user_agent
        else:
            self._session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 6.1; rv:45.0) Gecko/20100101 Firefox/45.0"
        self._session.headers["Accept-Language"] = "en-US"
        self._session.headers["Accept-Encoding"] = "gzip, deflate, br"
        self._session.headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
        self._session.max_redirects = 5
        self._session.verify = secure
        self._scope = Scope.FOLDER
        self._base = web.Request(base_url)
        self.auth_url = self._base.url
        self.is_logged_in = False

        if not compression:
            self._session.headers["accept-encoding"] = "identity"

        if proxies is not None and isinstance(proxies, dict):
            # ex: {'http': 'http://127.0.0.1:8080'}
            self._session.proxies = proxies

        self._auth_credentials = {}
        self._auth_method = "basic"

    def set_proxy(self, proxy=""):
        """Set a proxy to use for HTTP requests."""
        url_parts = urlparse(proxy)
        protocol = url_parts.scheme.lower()

        if protocol in ("http", "https", "socks"):
            if protocol == "socks":
                # socks5h proxy type won't leak DNS requests
                proxy = urlunparse(("socks5h", url_parts.netloc, '/', '', '', ''))
            else:
                proxy = urlunparse((url_parts.scheme, url_parts.netloc, '/', '', '', ''))

            # attach the proxy for http and https URLs
            self._session.proxies["http"] = proxy
            self._session.proxies["https"] = proxy
        else:
            raise ValueError("Unknown proxy type '{}'".format(protocol))

    @property
    def secure(self):
        return self._session.verify

    @secure.setter
    def secure(self, value: bool):
        self._session.verify = value

    @property
    def timeout(self):
        return self._timeout

    @timeout.setter
    def timeout(self, value: float):
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
        return self._session.headers["User-Agent"]

    @user_agent.setter
    def user_agent(self, value: str):
        """Setter for user-agent property"""
        if not isinstance(value, str):
            raise TypeError("Invalid type for User-Agent. Type str required.")
        self._session.headers["User-Agent"] = value

    def add_custom_header(self, key: str, value: str):
        """Set a HTTP header to use for every requests"""
        self._session.headers[key] = value

    @property
    def session_cookies(self):
        """Getter for session cookies (returns a RequestsCookieJar object)"""
        return self._session.cookies

    @session_cookies.setter
    def session_cookies(self, value):
        """Setter for session cookies (value may be a dict or RequestsCookieJar object)"""
        self._session.cookies = value

    def set_drop_cookies(self):
        self._session.cookies.set_policy(BlockAll())

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
            if self._auth_method == "basic":
                from requests.auth import HTTPBasicAuth
                self._session.auth = HTTPBasicAuth(username, password)
            elif self._auth_method == "digest":
                from requests.auth import HTTPDigestAuth
                self._session.auth = HTTPDigestAuth(username, password)
            elif self._auth_method == "ntlm":
                from requests_ntlm import HttpNtlmAuth
                self._session.auth = HttpNtlmAuth(username, password)
        elif self._auth_method == "kerberos":
            # On openSUSE, "zypper in krb5-devel" before installing the pip package
            from requests_kerberos import HTTPKerberosAuth
            self._session.auth = HTTPKerberosAuth()

    def try_login(self, auth_url: str):
        """Try to authenticate with the provided url and credentials."""
        if len(self._auth_credentials) != 2:
            print(_("Login failed") + " : " + _("Invalid credentials format"))
            return

        username, password = self._auth_credentials

        # Fetch the login page and try to extract the login form
        try:
            page = self.get(web.Request(auth_url), follow_redirects=True)

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

                login_response = self.send(
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
        except RequestException as error:
            print(_("[!] {} with url {}").format(error.__class__.__name__, auth_url))

    @retry(delay=1, times=3)
    def get(self, resource: web.Request, follow_redirects: bool = False, headers: dict = None) -> Page:
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
        try:
            response = self._session.get(
                resource.url,
                timeout=self._timeout,
                allow_redirects=follow_redirects,
                headers=headers,
                verify=self.secure
            )
        except ConnectionError as exception:
            # https://github.com/kennethreitz/requests/issues/2392
            # Unfortunately chunked transfer + timeout raise ConnectionError... let's fix that
            if "Read timed out" in str(exception):
                raise ReadTimeout("Request time out")

            raise exception

        return Page(response)

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
        loop = asyncio.get_running_loop()
        try:
            response = await loop.run_in_executor(
                None,
                functools.partial(
                    self._session.get,
                    resource.url,
                    timeout=self._timeout,
                    allow_redirects=follow_redirects,
                    headers=headers,
                    verify=self.secure
                )
            )
        except ConnectionError as exception:
            # https://github.com/kennethreitz/requests/issues/2392
            # Unfortunately chunked transfer + timeout raise ConnectionError... let's fix that
            if "Read timed out" in str(exception):
                raise ReadTimeout("Request time out")

            raise exception

        return Page(response)

    @retry(delay=1, times=3)
    def post(self, form: web.Request, follow_redirects: bool = False, headers: dict = None) -> Page:
        """Submit the given form, returns a Page on success, None otherwise.

        @type form: web.Request
        @type follow_redirects: bool
        @type headers: dict
        @rtype: Page
        """
        form_headers = {}
        if not form.is_multipart:
            # requests won't generate valid upload HTTP request if we give it a multipart/form-data content-type
            # valid requests with boundary info or made if file_params is not empty.
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

        try:
            response = self._session.post(
                form.path,  # We can use form.path with setting params or form.url without setting params
                params=form.get_params,
                data=post_params,
                files=file_params,
                headers=form_headers,
                timeout=self._timeout,
                allow_redirects=follow_redirects,
                verify=self.secure
            )
        except ConnectionError as exception:
            # https://github.com/kennethreitz/requests/issues/2392
            # Unfortunately chunked transfer + timeout raise ConnectionError... let's fix that
            if "Read timed out" in str(exception):
                raise ReadTimeout("Request time out")

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
            # requests won't generate valid upload HTTP request if we give it a multipart/form-data content-type
            # valid requests with boundary info or made if file_params is not empty.
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

        loop = asyncio.get_running_loop()
        try:
            response = await loop.run_in_executor(
                None,
                functools.partial(
                    self._session.post,
                    form.path,  # We can use form.path with setting params or form.url without setting params
                    params=form.get_params,
                    data=post_params,
                    files=file_params,
                    headers=form_headers,
                    timeout=self._timeout,
                    allow_redirects=follow_redirects,
                    verify=self.secure
                )
            )
        except ConnectionError as exception:
            # https://github.com/kennethreitz/requests/issues/2392
            # Unfortunately chunked transfer + timeout raise ConnectionError... let's fix that
            if "Read timed out" in str(exception):
                raise ReadTimeout("Request time out")

            raise exception

        return Page(response)

    @retry(delay=1, times=3)
    def request(
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

        try:
            response = self._session.request(
                method,
                form.url,
                data=form.post_params,
                files=form.file_params,
                headers=form_headers,
                allow_redirects=follow_redirects,
                timeout=self._timeout,
                verify=self.secure
            )
        except ConnectionError as exception:
            # https://github.com/kennethreitz/requests/issues/2392
            # Unfortunately chunked transfer + timeout raise ConnectionError... let's fix that
            if "Read timed out" in str(exception):
                raise ReadTimeout("Request time out")

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

        loop = asyncio.get_running_loop()
        try:
            response = await loop.run_in_executor(
                None,
                functools.partial(
                    self._session.request,
                    method,
                    form.url,
                    data=form.post_params,
                    files=form.file_params,
                    headers=form_headers,
                    allow_redirects=follow_redirects,
                    timeout=self._timeout,
                    verify=self.secure
                )
            )
        except ConnectionError as exception:
            # https://github.com/kennethreitz/requests/issues/2392
            # Unfortunately chunked transfer + timeout raise ConnectionError... let's fix that
            if "Read timed out" in str(exception):
                raise ReadTimeout("Request time out")

            raise exception

        return Page(response)

    def send(self, resource: web.Request, headers: dict = None, follow_redirects: bool = False) -> Page:
        if resource.method == "GET":
            page = self.get(resource, headers=headers, follow_redirects=follow_redirects)
        elif resource.method == "POST":
            page = self.post(resource, headers=headers, follow_redirects=follow_redirects)
        else:
            page = self.request(resource.method, resource, headers=headers, follow_redirects=follow_redirects)

        resource.status = page.status
        resource.set_headers(page.headers)
        return page

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

    def close(self):
        self._session.close()


class Explorer:
    def __init__(self, crawler_instance: Crawler):
        self._crawler = crawler_instance
        self._max_depth = 20
        self._max_page_size = MAX_PAGE_SIZE
        self._log = True
        self._bad_params = set()
        self._max_per_depth = 0
        self._max_files_per_dir = 0
        self._qs_limit = 0
        self._custom_404_codes = {}
        self._file_counts = defaultdict(int)
        self._pattern_counts = defaultdict(int)
        self._hostnames = set()

        self._regexes = []
        self._excluded_requests = []

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
                swf_links = swf.extract_links_from_swf(page.raw)
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

    def analyze(self, request) -> Tuple[bool, List]:
        if self._log:
            print("[+] {0}".format(request))

        dir_name = request.dir_name
        if dir_name not in self._custom_404_codes:
            invalid_page = "zqxj{0}.html".format("".join([choice(ascii_letters) for __ in range(10)]))
            invalid_resource = web.Request(dir_name + invalid_page)
            try:
                page = self._crawler.get(invalid_resource)
                self._custom_404_codes[dir_name] = page.status
            except RequestException:
                pass

        self._hostnames.add(request.hostname)

        resource_url = request.url

        try:
            page = self._crawler.send(request)
        except (TypeError, UnicodeDecodeError) as exception:
            print("{} with url {}".format(exception, resource_url))  # debug
            return False, []
        except SSLError:
            print(_("[!] SSL/TLS error occurred with URL"), resource_url)
            return False, []
        # TODO: what to do of connection errors ? sleep a while before retrying ?
        except ConnectionError:
            print(_("[!] Connection error with URL"), resource_url)
            return False, []
        except RequestException as error:
            print(_("[!] {} with url {}").format(error.__class__.__name__, resource_url))
            return False, []

        if self._max_files_per_dir:
            self._file_counts[dir_name] += 1

        if self._qs_limit and request.parameters_count:
            self._pattern_counts[request.pattern] += 1

        self._excluded_requests.append(request)  # thread safe

        # Sur les ressources statiques le content-length est généralement indiqué
        if self._max_page_size > 0:
            if page.raw_size > self._max_page_size:
                page.clean()
                return False, []

        if request.link_depth == self._max_depth:
            # We are at the edge of the depth so next links will have depth + 1 so to need to parse the page.
            return True, []

        resources = self.extract_links(page, request)
        # TODO: there's more situations where we would not want to attack the resource... must check this
        if page.is_directory_redirection:
            return False, resources

        return True, resources

    async def async_analyze(self, request) -> Tuple[bool, List]:
        if self._log:
            print("[+] {0}".format(request))

        dir_name = request.dir_name
        if dir_name not in self._custom_404_codes:
            invalid_page = "zqxj{0}.html".format("".join([choice(ascii_letters) for __ in range(10)]))
            invalid_resource = web.Request(dir_name + invalid_page)
            try:
                page = await self._crawler.async_get(invalid_resource)
                self._custom_404_codes[dir_name] = page.status
            except RequestException:
                pass

        self._hostnames.add(request.hostname)

        resource_url = request.url

        try:
            page = await self._crawler.async_send(request)
        except (TypeError, UnicodeDecodeError) as exception:
            print("{} with url {}".format(exception, resource_url))  # debug
            return False, []
        except SSLError:
            print(_("[!] SSL/TLS error occurred with URL"), resource_url)
            return False, []
        # TODO: what to do of connection errors ? sleep a while before retrying ?
        except ConnectionError:
            print(_("[!] Connection error with URL"), resource_url)
            return False, []
        except RequestException as error:
            print(_("[!] {} with url {}").format(error.__class__.__name__, resource_url))
            return False, []

        if self._max_files_per_dir:
            self._file_counts[dir_name] += 1

        if self._qs_limit and request.parameters_count:
            self._pattern_counts[request.pattern] += 1

        self._excluded_requests.append(request)  # thread safe

        # Sur les ressources statiques le content-length est généralement indiqué
        if self._max_page_size > 0:
            if page.raw_size > self._max_page_size:
                page.clean()
                return False, []

        if request.link_depth == self._max_depth:
            # We are at the edge of the depth so next links will have depth + 1 so to need to parse the page.
            return True, []

        resources = self.extract_links(page, request)
        # TODO: there's more situations where we would not want to attack the resource... must check this
        if page.is_directory_redirection:
            return False, resources

        return True, resources

    def explore(
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
        invalid_page = "zqxj{0}.html".format("".join([choice(ascii_letters) for __ in range(10)]))

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
                        self._excluded_requests.append(bad_request)

        self._crawler._session.stream = True

        if self._max_depth < 0:
            raise StopIteration

        while to_explore:
            request = to_explore.popleft()
            if not isinstance(request, web.Request):
                # We treat start_urls as if they are all valid URLs (ie in scope)
                request = web.Request(request, link_depth=0)

            if request in self._excluded_requests:
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

            success, resources = self.analyze(request)
            accepted_urls = 0
            for unfiltered_request in resources:
                if BAD_URL_REGEX.search(unfiltered_request.file_path):
                    # Malformed link due to HTML issues
                    continue

                if not self._crawler.is_in_scope(unfiltered_request):
                    continue

                if unfiltered_request.hostname not in self._hostnames:
                    unfiltered_request.link_depth = 0

                if unfiltered_request not in self._excluded_requests and unfiltered_request not in to_explore:
                    to_explore.append(unfiltered_request)
                    accepted_urls += 1

                # TODO: fix this, it doesn't looks valid
                # if self._max_per_depth and accepted_urls >= self._max_per_depth:
                #     break

        self._crawler._session.stream = False

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
                        self._excluded_requests.append(bad_request)

        self._crawler._session.stream = True

        if self._max_depth < 0:
            raise StopIteration

        task_to_request = {}
        while True:
            while to_explore:
                request = to_explore.popleft()
                if not isinstance(request, web.Request):
                    # We treat start_urls as if they are all valid URLs (ie in scope)
                    request = web.Request(request, link_depth=0)

                if request in self._excluded_requests:
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

            done, not_done = await asyncio.wait(
                task_to_request,
                timeout=0.25,
                return_when=asyncio.FIRST_COMPLETED
            )

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

                        if unfiltered_request not in self._excluded_requests and unfiltered_request not in to_explore:
                            to_explore.append(unfiltered_request)
                            accepted_urls += 1

                        # TODO: fix this, it doesn't looks valid
                        # if self._max_per_depth and accepted_urls >= self._max_per_depth:
                        #     break

                # remove the now completed task
                del task_to_request[task]

            if not task_to_request and not to_explore:
                break

        self._crawler._session.stream = False
