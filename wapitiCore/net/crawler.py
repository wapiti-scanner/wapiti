#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Crawler v2.4.0 - A web spider library
# This file is part of the Wapiti project (http://wapiti.sourceforge.io)
# Copyright (C) 2006-2020 Nicolas SURRIBAS
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
from functools import lru_cache
from urllib.parse import urlparse, urlunparse
from hashlib import md5
from http.client import IncompleteRead
import warnings
from ast import literal_eval
from collections import deque, defaultdict
from posixpath import normpath
import pickle
import math
import functools
from time import sleep

# Third-parties
import requests
from requests.packages.urllib3 import disable_warnings
from requests.packages.urllib3.exceptions import ReadTimeoutError
from requests.exceptions import ConnectionError, RequestException, ReadTimeout, SSLError
from requests.models import Response
from tld import get_fld
from tld.exceptions import TldDomainNotFound, TldBadUrl
from bs4 import BeautifulSoup
from bs4.element import Comment

# Internal libraries
from wapitiCore.language.language import _
from wapitiCore import parser_name
from wapitiCore.net import web
from wapitiCore.net import swf
from wapitiCore.net import lamejs

disable_warnings()
warnings.filterwarnings(action='ignore', category=UserWarning, module='bs4')
RE_JS_REDIR = re.compile(
    r"\b(window\.|document\.|top\.|self\.)?location(\.href)?\s*=\s*(\"|')(http[s]?://[^'\"]+\.[^'\"]+)\3\s*(;|}|$)"
)


class Scope(Enum):
    FOLDER = 1
    PAGE = 2
    URL = 3
    DOMAIN = 4
    PUNK = 5


MIME_TEXT_TYPES = ('text/', 'application/xml')
# Limit page size to 2MB
MAX_PAGE_SIZE = 2097152

JS_EVENTS = [
    'onabort', 'onblur', 'onchange', 'onclick', 'ondblclick',
    'ondragdrop', 'onerror', 'onfocus', 'onkeydown', 'onkeypress',
    'onkeyup', 'onload', 'onmousedown', 'onmousemove', 'onmouseout',
    'onmouseover', 'onmouseup', 'onmove', 'onreset', 'onresize',
    'onselect', 'onsubmit', 'onunload'
]

# This is ugly but let's keep it while there is not a js parser
COMMON_JS_STRINGS = {
    "Msxml2.XMLHTTP", "application/x-www-form-urlencoded", ".php", "text/xml",
    "about:blank", "Microsoft.XMLHTTP", "text/plain", "text/javascript",
    "application/x-shockwave-flash"
}

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

JS_SCHEME_REGEX = re.compile(r"^javascript:", re.I)
BAD_URL_REGEX = re.compile(r"https?:/[^/]+")


def not_empty(original_function):
    def wrapped(*args, **kwargs):
        generator = original_function(*args, **kwargs)
        for value in generator:
            if value:
                yield value
    return wrapped


class Page:
    def __init__(self, response: Response, url: str, empty: bool = False):
        """Create a new Page object.

        @type response: Response
        @param response: a requests Response instance.

        @type url: str
        @param url: URL of the Page.

        @type empty: bool
        @param empty: whether the Page is empty (body length == 0)"""
        self._response = response
        self._url = url
        self._base = None
        self._soup = None
        self._is_empty = empty
        try:
            self._fld = get_fld(url)
        except TldDomainNotFound:
            self._fld = urlparse(url).netloc

    @property
    def url(self) -> str:
        """Returns the URL of the current Page object

        @rtype: str
        """
        return self._url

    @property
    def headers(self):
        """Returns the dictionary of HTTP headers as sent by the web-server.

        @rtype: dict
        """
        return self._response.headers

    @property
    def cookies(self):
        return self._response.cookies

    @property
    @lru_cache(maxsize=2)
    def server(self) -> str:
        """The banner of the web-server software.

        @rtype: str
        """
        return self._response.headers.get("server", "")

    @property
    def is_plain(self) -> bool:
        """Returns True if the HTTP body is sent uncompressed, otherwise False.

        @rtype: bool
        """
        return self._response.headers.get("content-encoding", "identity") == "identity"

    @property
    @lru_cache(maxsize=2)
    def size(self) -> int:
        """Size of the web-page as specified in the Content-Length header,
        otherwise calculated from the actual HTML code.

        @rtype: int
        """
        if "content-length" in self._response.headers and self.is_plain:
            if self._response.headers.get("transfer-encoding", "") != "chunked":
                if "," in self._response.headers["content-length"]:
                    return int(self._response.headers["content-length"].split(",")[0].strip())
                elif ";" in self._response.headers["content-length"]:
                    return int(self._response.headers["content-length"].split(";")[0].strip())

                return int(self._response.headers["content-length"])
        return len(self.bytes)

    @property
    @lru_cache(maxsize=2)
    def raw_size(self) -> int:
        """Size of the HTTP body sent as raw bytes by the server.

        @rtype: int
        """
        if "content-length" in self._response.headers:
            if self._response.headers.get("transfer-encoding", "") != "chunked":
                if "," in self._response.headers["content-length"]:
                    return int(self._response.headers["content-length"].split(",")[0].strip())
                elif ";" in self._response.headers["content-length"]:
                    return int(self._response.headers["content-length"].split(";")[0].strip())

            return int(self._response.headers["content-length"])
        # permet de forcer le chargement du body
        if self.bytes:
            return self._response.raw.tell()
        return 0

    @property
    @lru_cache(maxsize=2)
    def delay(self):
        """Time in seconds it took to fetch the web-page.

        @rtype: float
        """
        return self._response.elapsed.total_seconds()

    @property
    def content(self) -> str:
        """HTML source code of the web-page as str"""
        if self._is_empty:
            return ""

        try:
            return self._response.text
        except (ConnectionError, OSError, IncompleteRead):
            return ""

    @property
    def bytes(self) -> bytes:
        """HTTP body response as raw bytes"""
        if self._is_empty:
            return b""

        try:
            return self._response.content
        except (ConnectionError, OSError, IncompleteRead):
            return b""

    @property
    def raw(self):
        return self._response.raw

    @property
    def json(self):
        if not self.content:
            return None

        try:
            return self._response.json()
        except ValueError:
            pass

        try:
            return literal_eval(self._response.content)
        except ValueError:
            pass

        return None

    @property
    @lru_cache(maxsize=2)
    def md5(self) -> str:
        """Return the MD5 hash (hex representation) of the content of the webpage"""
        return md5(self.bytes).hexdigest()

    @property
    @lru_cache(maxsize=2)
    def status(self) -> int:
        """Returns the HTTP status code as int"""
        return self._response.status_code

    @property
    @lru_cache(maxsize=2)
    def type(self) -> str:
        """Content-Type of the web-page as returned by the server."""
        return self._response.headers.get("content-type", "").lower()

    @not_empty
    def _scripts(self):
        url_parts = urlparse(self._base or self._url)
        scheme = url_parts.scheme

        for tag in self.soup.find_all("script", src=True):
            parts = urlparse(tag["src"])

            if parts.scheme:
                if parts.netloc:
                    # Full absolute URL
                    script_url = urlunparse((parts.scheme, parts.netloc, parts.path, parts.params, parts.query, ''))
                else:
                    # Malformed absolute URL (no host)
                    continue
            elif parts.netloc:
                # Protocol relative URL
                script_url = urlunparse((scheme, parts.netloc, parts.path, parts.params, parts.query, ''))
            else:
                # Internal relative URL
                script_url = urlunparse(('', '', parts.path, parts.params, parts.query, ''))
            yield script_url

    @property
    def soup(self):
        """Returns a parsable BeautifulSoup representation of the webpage.

        @rtype: BeautifulSoup
        """
        if self._soup is None:
            if "text" in self.type:
                self._soup = BeautifulSoup(self.content, parser_name)
                base_tag = self._soup.find("base", href=True)
                if base_tag:
                    base_parts = urlparse(base_tag["href"])
                    current = urlparse(self._url)
                    base_path = base_parts.path or "/"
                    base_path = normpath(base_path.replace("\\", "/"))
                    # https://stackoverflow.com/questions/7816818/why-doesnt-os-normpath-collapse-a-leading-double-slash
                    base_path = re.sub(r"^/{2,}", "/", base_path)
                    # I guess a base url should always be a directory
                    if not base_path.endswith('/'):
                        base_path += '/'

                    self._base = urlunparse(
                        (
                            base_parts.scheme or current.scheme,
                            base_parts.netloc or current.netloc,
                            base_path, "", "", ""
                        )
                    )
            else:
                self._soup = BeautifulSoup('', parser_name)
        return self._soup

    def clean(self):
        if self._soup is not None:
            self._soup.decompose()
            del self._soup
        self._response.raw.close()

    @property
    @lru_cache(maxsize=2)
    def scripts(self) -> list:
        """List of URLs of imported JS scripts. Query strings and anchors are removed.

        @rtype: list
        """
        return [self.make_absolute(script_url) for script_url in self._scripts()]

    def iter_frames(self):
        """Returns the absolute URLs of frames loaded in the webpage."""
        for tag in self.soup.find_all(["frame", "iframe"], src=True):
            value = tag["src"].split("#")[0].strip()
            if value:
                fixed_url = self.make_absolute(value)
                if fixed_url:
                    yield fixed_url

    @property
    @lru_cache(maxsize=2)
    def redirection_url(self):
        """Returns the fixed URL sent through the Location header if set otherwise returns None."""
        if self._response.is_redirect or self._response.is_permanent_redirect:
            if "location" in self._response.headers:
                return self.make_absolute(self._response.headers["location"])
        return ""

    @property
    def is_directory_redirection(self):
        if not self.redirection_url:
            return False
        if self.url + "/" == self.redirection_url:
            return True
        return False

    @not_empty
    def _iter_raw_links(self):
        """Generator returning all raw URLs found in HTML "a href", frame's src tags and redirections."""
        yield self.redirection_url

        for tag in self.soup.find_all("a", href=True):
            yield tag["href"].split("#")[0].strip()

        for tag in self.soup.find_all(["frame", "iframe"], src=True):
            yield tag["src"].split("#")[0].strip()

        for tag in self.soup.find_all("form", action=True):
            yield tag["action"]

        for tag in self.soup.find_all("button", formaction=True):
            yield tag["formaction"]

    def make_absolute(self, link: str) -> str:
        """Convert a relative URL to an absolute one (with scheme, host, path, etc) and use the base href if present.

        @type link: str
        @param link: A relative URL.
        @rtype: str
        """
        if not link.strip():
            return ""

        current_url_parts = urlparse(self._base or self._url)
        scheme = current_url_parts.scheme
        domain = current_url_parts.netloc
        path = current_url_parts.path
        params = current_url_parts.params

        try:
            parts = urlparse(link)
        except ValueError:
            # malformed URL, for example "Invalid IPv6 URL" errors due to square brackets
            return ""

        query_string = parts.query
        url_path = parts.path or '/'
        url_path = normpath(url_path.replace("\\", "/"))

        # https://stackoverflow.com/questions/7816818/why-doesnt-os-normpath-collapse-a-leading-double-slash
        url_path = re.sub(r"^/{2,}", "/", url_path)

        # normpath removes the trailing slash so we must add it if necessary
        if (parts.path.endswith(('/', '/.')) or parts.path == '.') and not url_path.endswith('/'):
            url_path += '/'

        # a hack for auto-generated Apache directory index
        if query_string in [
            "C=D;O=A", "C=D;O=D", "C=M;O=A", "C=M;O=D",
            "C=N;O=A", "C=N;O=D", "C=S;O=A", "C=S;O=D"
        ]:
            query_string = ""

        if parts.scheme:
            if parts.scheme == "http" or parts.scheme == "https":
                if parts.netloc and parts.netloc != "http:":  # malformed url
                    netloc = parts.netloc
                    try:
                        # urlparse tries to convert port in base10. an error is raised if port is not digits
                        port = parts.port
                    except ValueError:
                        port = None

                    if (parts.scheme == "https" and port == 443) or (parts.scheme == "http" and port == 80):
                        # Beware of IPv6 addresses
                        netloc = parts.netloc.rsplit(":", 1)[0]
                    return urlunparse((parts.scheme, netloc, url_path, parts.params, query_string, ''))
        elif link.startswith("//"):
            if parts.netloc:
                netloc = parts.netloc
                try:
                    port = parts.port
                except ValueError:
                    port = None

                if (parts.scheme == "https" and port == 443) or (parts.scheme == "http" and port == 80):
                    # Beware of IPv6 addresses
                    netloc = parts.netloc.rsplit(":", 1)[0]
                return urlunparse((scheme, netloc, url_path or '/', parts.params, query_string, ''))
        elif link.startswith("/"):
            return urlunparse((scheme, domain, url_path, parts.params, query_string, ''))
        elif link.startswith("?"):
            return urlunparse((scheme, domain, path, params, query_string, ''))
        elif link == "" or link.startswith("#"):
            return self._url
        else:
            # relative path to file, subdirectory or parent directory
            current_directory = path if path.endswith("/") else path.rsplit("/", 1)[0] + "/"
            # new_path = (current_directory + parts.path).replace("//", "/").replace("/./", "/")

            new_path = normpath(current_directory + url_path)
            if url_path.endswith('/') and not new_path.endswith('/'):
                new_path += '/'

            # links going to a parent directory (..)
            # while re.search(r"/([~:!,;%a-zA-Z0-9\.\-+_]+)/\.\./", new_path) is not None:
            #     new_path = re.sub(r"/([~:!,;%a-zA-Z0-9\.\-+_]+)/\.\./", "/", new_path)
            # while re.search("/\./", new_path) is not None:
            #     new_path = re.sub("/\./", "/", new_path)
            # if new_path == "":
            #     new_path = '/'

            # Fix for path going back up the root directory (eg: http://srv/../../dir/)
            # new_path = re.sub(r'^(/?\.\.//*)*', '', new_path)
            # if not new_path.startswith('/'):
            #     new_path = '/' + new_path

            return urlunparse((scheme, domain, new_path, parts.params, query_string, ''))
        # Returns an empty string for everything that we don't want to deal with
        return ""

    @not_empty
    def _iter_links(self):
        """Generator returning all links in the webpage. Beware of duplicates.

        @rtype: generator
        """
        for link in self._iter_raw_links():
            yield self.make_absolute(link)

    @property
    def links(self) -> list:
        """List of unique links in the webpage.

        @rtype: list
        """
        return list(set(self._iter_links()))

    def is_external_to_domain(self, url: str) -> bool:
        """Returns True if url is under another TLD than the crawled URL, False otherwise.

        @type url: str
        @param url: An absolute URL (with protocol prefix)
        @rtype: bool
        """
        try:
            fld = get_fld(url)
        except TldDomainNotFound:
            # Not yet known TLD or IP address or local hostname
            fld = urlparse(url).netloc
        except TldBadUrl:
            fld = None
        return fld != self._fld

    def is_internal_to_domain(self, url: str) -> bool:
        """Returns True if url is under the same TLD as the crawled URL, False otherwise.

        @type url: str
        @rtype: bool
        """
        return not self.is_external_to_domain(url)

    @property
    def title(self):
        """Returns the content of the title HTML tag"""
        if self.soup.head is not None:
            title = self.soup.head.title
            if title is not None:
                return title.text
        return ""

    @property
    def base_url(self):
        """Returns the base URL used for links in the webpage or None if not specified"""
        __ = self.soup
        return self._base

    def _meta(self, name):
        if self.soup.head is not None:
            tag = self.soup.head.find("meta", attrs={"name": name}, content=True)
            if tag is not None:
                return tag["content"]
        return ""

    @property
    def description(self) -> str:
        """Returns the content of the meta description tag in the HTML header.

        @rtype: str
        """
        return self._meta("description")

    @property
    def keywords(self):
        """Returns the content of the meta keywords tag in the HTML header.

        @rtype: list
        """
        return self._meta("keywords").split(",")

    @property
    def generator(self) -> str:
        """Returns the content of the meta generator tag in the HTML header.

        @rtype: str
        """
        return self._meta("generator")

    @property
    def text_only(self):
        """Returns the displayed text of a webpage (without HTML tags)"""
        if "text" in self.type and self.size:
            texts = self.soup.findAll(text=True)

            def is_visible(element):
                if len(element.strip()) == 0:
                    return False
                elif isinstance(element, Comment):
                    return False
                elif element.parent.name in ["style", "script", "[document]", "head", "title"]:
                    return False
                return True

            text = " ".join(filter(is_visible, texts)).replace("\r\n", " ").replace("\n", " ")
            return text
        return ""

    def empty(self):
        """Modify the current Page object to make it appears as if the content-length was 0."""
        self._is_empty = True
        self.clean()

    @property
    def encoding(self):
        """Return the detected encoding for the page."""
        if self._response.encoding:
            return self._response.encoding.upper()
        return None

    @property
    def apparent_encoding(self):
        """Return the detected encoding for the page."""
        if self._response.apparent_encoding:
            return self._response.apparent_encoding.upper()
        return None

    @encoding.setter
    def encoding(self, new_encoding):
        """Change the encoding used for obtaining Page content"""
        self._response.encoding = new_encoding

    @property
    def favicon_url(self) -> str:
        """Returns the URL of the favicon specified in the webpage.

        This method looks for a link tag with a rel value of "icon" or "shortcut icon".
        URL defaults to "/favicon.ico" if no such tag was found in the webpage.

        @rtype: str
        """

        icon_tag = self.soup.find("link", rel=re.compile(r".*\bicon\b.*", flags=re.I), href=True)
        if icon_tag:
            icon_uri = icon_tag["href"]
            if icon_uri.startswith("data:"):
                return ""
            else:
                return self.make_absolute(icon_uri)
        return self.make_absolute("/favicon.ico")

    @property
    def images_urls(self):
        """Returns a list of full images URLs found in the webpage.

        @rtype: list
        """
        urls = set()
        for image_tag in self.soup.find_all("img", src=True):
            image_rel_url = image_tag["src"]
            if not image_rel_url or image_rel_url.startswith("#"):
                continue

            image_url = self.make_absolute(image_rel_url)
            if image_url:
                urls.add(image_url)
        return list(urls)

    @property
    @not_empty
    def extra_urls(self):
        # Extract URLs for special tags attributes that may reference any kind of resource.
        # See http://htmlreference.io/
        for tag in self.soup.find_all(["area", "base", "link"], href=True):
            yield self.make_absolute(tag["href"])
        for tag in self.soup.find_all(["audio", "embed", "img", "script", "source", "track", "video"], src=True):
            yield self.make_absolute(tag["src"])
        for tag in self.soup.find_all(["blockquote", "del", "ins", "q"], cite=True):
            yield self.make_absolute(tag["cite"])
        for tag in self.soup.find_all("object", data=True):
            yield self.make_absolute(tag["data"])
        for tag in self.soup.find_all("param", attrs={"name": "movie", "value": True}):
            yield self.make_absolute(tag["value"])
        for tag in self.soup.find_all(["img", "source"], srcset=True):
            for source_desc in tag["srcset"].split(","):
                url = source_desc.strip().split(" ")[0]
                if url:
                    yield self.make_absolute(url)

        for attribute in JS_EVENTS:
            for tag in self.soup.find_all(None, attrs={attribute: True}):
                for url in lamejs.LameJs(tag[attribute]).get_links():
                    yield self.make_absolute(url)

        for script in self.soup.find_all("script", string=True):
            urls = lamejs.LameJs(script.string).get_links()

            # too many annoying false positives
            # candidates = re.findall(r'"([A-Za-z0-9_=#&%.+?/-]*)"', script.string)
            # candidates += re.findall(r"'([A-Za-z0-9_=#&%.+?/-]*)'", script.string)
            #
            # allowed_ext = [".php", ".asp", ".xml", ".js", ".json", ".jsp"]
            # for jstr in candidates:
            #     if "." in jstr and jstr not in COMMON_JS_STRINGS:
            #         for ext in allowed_ext:
            #             if ext in jstr:
            #                 urls.append(jstr)
            #                 break
            for url in urls:
                yield self.make_absolute(url)

        for tag in self.soup.find_all("a", href=JS_SCHEME_REGEX):
            for url in lamejs.LameJs(tag["href"].split(':', 1)[1]).get_links():
                yield self.make_absolute(url)

        for tag in self.soup.find_all("form", action=JS_SCHEME_REGEX):
            for url in lamejs.LameJs(tag["action"].split(':', 1)[1]).get_links():
                yield self.make_absolute(url)

    @property
    def js_redirections(self):
        """Returns a list or redirection URLs found in the javascript code of the webpage.

        @rtype: list
        """
        urls = set()

        for script in self.soup.find_all("script"):
            js = script.get_text(" ", strip=True)
            search = re.search(RE_JS_REDIR, js)
            if search:
                url = self.make_absolute(search.group(4))
                if url:
                    urls.add(url)
        return list(urls)

    @property
    def html_redirections(self):
        urls = set()
        for meta_tag in self.soup.find_all("meta", attrs={"content": True, "http-equiv": True}):
            if meta_tag and meta_tag["http-equiv"].lower() == "refresh":
                content_str = meta_tag["content"].lower()
                url_eq_idx = content_str.find("url=")
                if url_eq_idx >= 0:
                    url = meta_tag["content"][url_eq_idx + 4:]
                    if url:
                        urls.add(self.make_absolute(url))
        return [url for url in urls if url]

    @property
    def all_redirections(self):
        result = set()
        if self.redirection_url:
            result.add(self.redirection_url)
        result.update(self.js_redirections)
        result.update(self.html_redirections)
        return result

    def iter_forms(self, autofill=True):
        """Returns a generator of Request extracted from the Page.

        @rtype: generator
        """
        for form in self.soup.find_all("form"):
            url = self.make_absolute(form.attrs.get("action", "").strip() or self._url)
            # If no method is specified then it's GET. If an invalid method is set it's GET.
            method = "POST" if form.attrs.get("method", "GET").upper() == "POST" else "GET"
            enctype = "" if method == "GET" else form.attrs.get("enctype", "application/x-www-form-urlencoded").lower()
            get_params = []
            post_params = []
            # If the form must be sent in multipart, everything should be given to requests in the files parameter
            # but internally we use the file_params list only for file inputs sent with multipart (as they must be
            # threated differently in persister). Crawler.post() method will join post_params and file_params for us
            # if the enctype is multipart.
            file_params = []
            form_actions = set()

            defaults = {
                "checkbox": "default",
                "color": "#bada55",
                "date": "2019-03-03",
                "datetime": "2019-03-03T20:35:34.32",
                "datetime-local": "2019-03-03T22:41",
                "email": "wapiti2019@mailinator.com",
                "file": ["pix.gif", "GIF89a", "image/gif"],
                "hidden": "default",
                "month": "2019-03",
                "number": "1337",
                "password": "Letm3in_",  # 8 characters with uppercase, digit and special char for common rules
                "radio": "beton",  # priv8 j0k3
                "range": "37",
                "search": "default",
                "submit": "submit",
                "tel": "0606060606",
                "text": "default",
                "time": "13:37",
                "url": "http://wapiti.sf.net/",
                "week": "2019-W24"
            }

            radio_inputs = {}
            for input_field in form.find_all("input", attrs={"name": True}):
                input_type = input_field.attrs.get("type", "text").lower()

                if input_type in {"reset", "button"}:
                    # Those input types doesn't send any value
                    continue
                elif input_type == "image":
                    if method == "GET":
                        get_params.append([input_field["name"] + ".x", "1"])
                        get_params.append([input_field["name"] + ".y", "1"])
                    else:
                        post_params.append([input_field["name"] + ".x", "1"])
                        post_params.append([input_field["name"] + ".y", "1"])
                elif input_type in defaults:
                    if input_type == "text" and "mail" in input_field["name"] and autofill:
                        # If an input text match name "mail" then put a valid email address in it
                        input_value = defaults["email"]
                    elif input_type == "text" and "pass" in input_field["name"] or \
                            "pwd" in input_field["name"] and autofill:
                        # Looks like a text field but waiting for a password
                        input_value = defaults["password"]
                    else:
                        input_value = input_field.get("value", defaults[input_type] if autofill else "")

                    if input_type == "file":
                        # With file inputs the content is only sent if the method is POST and enctype multipart
                        # otherwise only the file name is sent.
                        # Having a default value set in HTML for a file input doesn't make sense... force our own.
                        if method == "GET":
                            get_params.append([input_field["name"], "pix.gif"])
                        else:
                            if "multipart" in enctype:
                                file_params.append([input_field["name"], defaults["file"]])
                            else:
                                post_params.append([input_field["name"], "pix.gif"])
                    elif input_type == "radio":
                        # Do not put in forms now, do it at the end
                        radio_inputs[input_field["name"]] = input_value
                    else:
                        if method == "GET":
                            get_params.append([input_field["name"], input_value])
                        else:
                            post_params.append([input_field["name"], input_value])

            # A formaction doesn't need a name
            for input_field in form.find_all("input", attrs={"formaction": True}):
                form_actions.add(self.make_absolute(input_field["formaction"].strip() or self._url))

            for button_field in form.find_all("button", formaction=True):
                # If formaction is empty it basically send to the current URL
                # which can be different from the defined action attribute on the form...
                form_actions.add(self.make_absolute(button_field["formaction"].strip() or self._url))

            if form.find("input", attrs={"name": False, "type": "image"}):
                # Unnamed input type file => names will be set as x and y
                if method == "GET":
                    get_params.append(["x", "1"])
                    get_params.append(["y", "1"])
                else:
                    post_params.append(["x", "1"])
                    post_params.append(["y", "1"])

            for select in form.find_all("select", attrs={"name": True}):
                all_values = []
                selected_value = None
                for option in select.find_all("option", value=True):
                    all_values.append(option["value"])
                    if "selected" in option.attrs:
                        selected_value = option["value"]

                if selected_value is None and all_values:
                    # First value may be a placeholder but last entry should be valid
                    selected_value = all_values[-1]

                if method == "GET":
                    get_params.append([select["name"], selected_value])
                else:
                    post_params.append([select["name"], selected_value])

            # if form.find("input", attrs={"type": "image", "name": False}):
            #     new_form.add_image_field()

            for text_area in form.find_all("textarea", attrs={"name": True}):
                if method == "GET":
                    get_params.append([text_area["name"], "Hi there!" if autofill else ""])
                else:
                    post_params.append([text_area["name"], "Hi there!" if autofill else ""])

            # I guess I should raise a new form for every possible radio values...
            # For the moment, just use the last value
            for radio_name, radio_value in radio_inputs.items():
                if method == "GET":
                    get_params.append([radio_name, radio_value])
                else:
                    post_params.append([radio_name, radio_value])

            if method == "POST" and not post_params and not file_params:
                # Ignore empty forms. Those are either webdev issues or forms having only "button" types that
                # only rely on JS code.
                continue

            # First raise the form with the URL specified in the action attribute
            new_form = web.Request(
                url,
                method=method,
                get_params=get_params,
                post_params=post_params,
                file_params=file_params,
                encoding=self.apparent_encoding,
                referer=self.url,
                enctype=enctype
            )
            yield new_form

            # Then if we saw some formaction attribute, raise the form with the given formaction URL
            for url in form_actions:
                new_form = web.Request(
                    url,
                    method=method,
                    get_params=get_params,
                    post_params=post_params,
                    file_params=file_params,
                    encoding=self.apparent_encoding,
                    referer=self.url,
                    enctype=enctype
                )
                yield new_form


def wildcard_translate(pattern):
    """Translate a wildcard PATTERN to a regular expression object.

    This is largely inspired by fnmatch.translate.
    """

    i, n = 0, len(pattern)
    res = ''
    while i < n:
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
        self._session.max_redirects = 5
        self._session.verify = secure
        self._scope = Scope.FOLDER
        self._base = web.Request(base_url)

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
                headers=headers
            )
        except ConnectionError as exception:
            # https://github.com/kennethreitz/requests/issues/2392
            # Unfortunately chunked transfer + timeout raise ConnectionError... let's fix that
            if "Read timed out" in str(exception):
                raise ReadTimeout("Request time out")
            else:
                raise exception

        return Page(response, resource.url)

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
            else:
                raise exception

        return Page(response, form.url)

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
                timeout=self._timeout
            )
        except ConnectionError as exception:
            # https://github.com/kennethreitz/requests/issues/2392
            # Unfortunately chunked transfer + timeout raise ConnectionError... let's fix that
            if "Read timed out" in str(exception):
                raise ReadTimeout("Request time out")
            else:
                raise exception

        return Page(response, form.url)

    def send(self, resource: web.Request, headers: dict = None, follow_redirects: bool = False) -> Page:
        if resource.method == "GET":
            page = self.get(resource, headers=headers, follow_redirects=follow_redirects)
        elif resource.method == "POST":
            page = self.post(resource, headers=headers, follow_redirects=follow_redirects)
        else:
            page = self.request(resource.method, resource, headers=headers, follow_redirects=follow_redirects)

        resource.size = page.size
        resource.duration = page.delay
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

    def load_saved_state(self, pickle_file: str):
        with open(pickle_file, "wb") as fd:
            self._custom_404_codes = {}
            self._file_counts = defaultdict(int)
            self._pattern_counts = defaultdict(int)
            self._hostnames = set()
            pickle.dump(
                {
                    "custom_404_codes": self._custom_404_codes,
                    "file_counts": self._file_counts,
                    "pattern_counts": self._pattern_counts,
                    "hostnames": self._hostnames
                },
                fd,
                pickle.HIGHEST_PROTOCOL
            )

    def save_state(self, pickle_file: str):
        try:
            with open(pickle_file, "rb") as fd:
                data = pickle.load(fd)
                self._custom_404_codes = data["custom_404_codes"]
                self._file_counts = data["file_counts"]
                self._pattern_counts = data["pattern_counts"]
                self._hostnames = data["hostnames"]
        except FileNotFoundError:
            pass

    def explore(
            self,
            urls: deque,
            excluded_urls: list = None
    ):
        """Explore a single TLD or the whole Web starting with an URL

        @param urls: A list of URL to scan the scan with.
        @type urls: list
        @param excluded_urls: A list of URLs to skip. Request objects or strings which may contain wildcards.
        @type excluded_urls: list

        @rtype: generator
        """
        # explored_urls = []
        to_explore = deque()
        invalid_page = "zqxj{0}.html".format("".join([choice(ascii_letters) for __ in range(10)]))

        # Common params used for tracking or other stuff
        self._bad_params.update(
            [
                "utm_source", "utm_medium", "utm_content", "utm_campaign", "g-recaptcha-response"
            ]
        )

        while True:
            try:
                start_url = urls.popleft()
                if isinstance(start_url, web.Request):
                    to_explore.append(start_url)
                else:
                    # We treat start_urls as if they are all valid URLs (ie in scope)
                    to_explore.append(web.Request(start_url, link_depth=0))
            except IndexError:
                break

        for request in to_explore:
            urls.append(request)

        # This is only for semantic
        to_explore = urls

        self._crawler._session.stream = True

        if self._max_depth < 0:
            raise StopIteration

        regexes = []
        excluded_requests = []

        if isinstance(excluded_urls, list):
            while True:
                try:
                    excluded_url = excluded_urls.pop()
                except IndexError:
                    break
                else:
                    if isinstance(excluded_url, str):
                        regexes.append(wildcard_translate(excluded_url))
                    elif isinstance(excluded_url, web.Request):
                        excluded_requests.append(excluded_requests)

        def is_forbidden(candidate_url):
            return any(regex.match(candidate_url) for regex in regexes)

        while to_explore:
            request = to_explore.popleft()
            resource_url = request.url
            is_excluded = False

            if request.link_depth > self._max_depth:
                continue

            dir_name = request.dir_name
            if self._max_files_per_dir and self._file_counts[dir_name] >= self._max_files_per_dir:
                continue

            # Won't enter if qs_limit is 0 (aka insane mode)
            if self._qs_limit:
                if len(request):
                    try:
                        if self._pattern_counts[
                            request.pattern
                        ] >= 220 / (math.exp(len(request) * self._qs_limit) ** 2):
                            continue
                    except OverflowError:
                        # Oh boy... that's not good to try to attack a form with more than 600 input fields
                        # but I guess insane mode can do it as it is insane
                        continue

            if is_forbidden(resource_url):
                continue

            for known_resource in excluded_requests:
                if known_resource == request:
                    is_excluded = True
                    break

            if is_excluded:
                continue

            if self._log:
                print("[+] {0}".format(request))

            if dir_name not in self._custom_404_codes:
                invalid_resource = web.Request(dir_name + invalid_page)
                try:
                    page = self._crawler.get(invalid_resource)
                    self._custom_404_codes[dir_name] = page.status
                except RequestException:
                    pass

            self._hostnames.add(request.hostname)

            try:
                page = self._crawler.send(request)
            except (TypeError, UnicodeDecodeError) as exception:
                print("{} with url {}".format(exception, resource_url))  # debug
                continue
            except SSLError:
                print(_("[!] SSL/TLS error occurred with URL"), resource_url)
                continue
            # TODO: what to do of connection errors ? sleep a while before retrying ?
            except ConnectionError:
                print(_("[!] Connection error with URL"), resource_url)
                continue
            except RequestException as error:
                print(_("[!] {} with url {}").format(error.__class__.__name__, resource_url))
                continue

            if self._max_files_per_dir:
                self._file_counts[dir_name] += 1

            if self._qs_limit and len(request):
                self._pattern_counts[request.pattern] += 1

            excluded_urls.append(request)

            # Sur les ressources statiques le content-length est généralement indiqué
            if self._max_page_size > 0:
                if page.raw_size > self._max_page_size:
                    page.clean()
                    continue

            # TODO: there's more situations where we would not want to attack the resource... must check this
            if not page.is_directory_redirection:
                yield request

            if request.link_depth == self._max_depth:
                # We are at the edge of the depth so next links will have depth + 1 so to need to parse the page.
                continue

            swf_links = []
            js_links = []
            allowed_links = []

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

                        if form not in excluded_urls and form not in to_explore:
                            to_explore.append(form)

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

            accepted_urls = 0
            for new_url in set(allowed_links):
                if new_url == "":
                    continue

                if is_forbidden(new_url):
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

                new_url = web.Request(path, get_params=get_params, link_depth=depth)

                if BAD_URL_REGEX.search(new_url.file_path):
                    # Malformed link due to HTML issues
                    continue

                if not self._crawler.is_in_scope(new_url):
                    continue

                if new_url.hostname not in self._hostnames:
                    new_url.link_depth = 0

                if new_url not in excluded_urls and new_url not in to_explore:
                    to_explore.append(new_url)
                    accepted_urls += 1

                if self._max_per_depth and accepted_urls >= self._max_per_depth:
                    break

        self._crawler._session.stream = False
