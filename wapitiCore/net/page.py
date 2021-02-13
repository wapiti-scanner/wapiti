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
from functools import lru_cache
from urllib.parse import urlparse, urlunparse
from hashlib import md5
from http.client import IncompleteRead
import warnings
from ast import literal_eval
from posixpath import normpath

# Third-parties
from requests.packages.urllib3 import disable_warnings
from requests.exceptions import ConnectionError
from requests.models import Response
from tld import get_fld
from tld.exceptions import TldDomainNotFound, TldBadUrl
from bs4 import BeautifulSoup
from bs4.element import Comment

# Internal libraries
from wapitiCore import parser_name
from wapitiCore.net import web
from wapitiCore.net import lamejs

disable_warnings()
warnings.filterwarnings(action='ignore', category=UserWarning, module='bs4')
RE_JS_REDIR = re.compile(
    r"\b(window\.|document\.|top\.|self\.)?location(\.href)?\s*=\s*(\"|')(http[s]?://[^'\"]+\.[^'\"]+)\3\s*(;|}|$)"
)


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


JS_SCHEME_REGEX = re.compile(r"^javascript:", re.I)


def not_empty(original_function):
    def wrapped(*args, **kwargs):
        generator = original_function(*args, **kwargs)
        for value in generator:
            if value:
                yield value
    return wrapped


class Page:
    def __init__(self, response: Response, empty: bool = False):
        """Create a new Page object.

        @type response: Response
        @param response: a requests Response instance.

        @type empty: bool
        @param empty: whether the Page is empty (body length == 0)"""
        self._response = response
        self._base = None
        self._soup = None
        self._is_empty = empty
        try:
            self._fld = get_fld(response.url)
        except TldDomainNotFound:
            self._fld = urlparse(response.url).netloc

    @property
    def url(self) -> str:
        """Returns the URL of the current Page object

        @rtype: str
        """
        return self._response.url

    @property
    def history(self) -> list:
        """Returns a list of precedent webpages in case of redirection

        @rtype: list
        """
        return [Page(response) for response in self._response.history]

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
                if ";" in self._response.headers["content-length"]:
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
                if ";" in self._response.headers["content-length"]:
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
        url_parts = urlparse(self._base or self.url)
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
                    current = urlparse(self.url)
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

        current_url_parts = urlparse(self._base or self.url)
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
            return self.url
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

    @property
    def metas(self) -> dict:
        """Returns a dictionary of all metas tags with name attribute as the key and content attribute as the value."""
        metas = {}
        if self.soup.head is not None:
            for meta_tag in self.soup.head.find_all("meta", attrs={"name": True, "content": True}, content=True):
                tag_name = meta_tag["name"].lower().strip()
                if tag_name:
                    metas[tag_name] = meta_tag["content"]

        return metas

    @property
    def description(self) -> str:
        """Returns the content of the meta description tag in the HTML header.

        @rtype: str
        """
        return self.metas.get("description", "")

    @property
    def keywords(self):
        """Returns the content of the meta keywords tag in the HTML header.

        @rtype: list
        """
        return self.metas.get("keywords", "").split(",")

    @property
    def generator(self) -> str:
        """Returns the content of the meta generator tag in the HTML header.

        @rtype: str
        """
        return self.metas.get("generator", "")

    @property
    def text_only(self):
        """Returns the displayed text of a webpage (without HTML tags)"""
        if "text" in self.type and self.size:
            texts = self.soup.findAll(text=True)

            def is_visible(element):
                if len(element.strip()) == 0:
                    return False
                if isinstance(element, Comment):
                    return False
                if element.parent.name in ["style", "script", "[document]", "head", "title"]:
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

        for script in self.soup.find_all("script", text=True):
            j_script = script.string.strip()
            if not j_script:
                continue

            search = re.search(RE_JS_REDIR, j_script)
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
            url = self.make_absolute(form.attrs.get("action", "").strip() or self.url)
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
                "email": "wapiti2021@mailinator.com",
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
                "url": "https://wapiti.sourceforge.io/",
                "username": "alice",
                "week": "2019-W24"
            }

            radio_inputs = {}
            for input_field in form.find_all("input", attrs={"name": True}):
                input_type = input_field.attrs.get("type", "text").lower()

                if input_type in {"reset", "button"}:
                    # Those input types doesn't send any value
                    continue
                if input_type == "image":
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
                    elif input_type == "text" and "user" in input_field["name"] or \
                            "login" in input_field["name"] and autofill:
                        input_value = defaults["username"]
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
                form_actions.add(self.make_absolute(input_field["formaction"].strip() or self.url))

            for button_field in form.find_all("button", formaction=True):
                # If formaction is empty it basically send to the current URL
                # which can be different from the defined action attribute on the form...
                form_actions.add(self.make_absolute(button_field["formaction"].strip() or self.url))

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

    def find_login_form(self):
        """Returns the login Request extracted from the Page, the username and password fields."""

        for form in self.soup.find_all("form"):
            username_field_idx = []
            password_field_idx = []

            for i, input_field in enumerate(form.find_all("input")):
                input_type = input_field.attrs.get("type", "text").lower()
                input_name = input_field.attrs.get("name", "undefined").lower()
                input_id = input_field.attrs.get("id", "undefined").lower()
                if input_type == "email":
                    username_field_idx.append(i)

                elif input_type == "text" and (
                        any(field_name in input_name for field_name in ["mail", "user", "login", "name"]) or
                        any(field_id in input_id for field_id in ["mail", "user", "login", "name"])
                ):
                    username_field_idx.append(i)

                elif input_type == "password":
                    password_field_idx.append(i)

            # ensure login form
            if len(username_field_idx) == 1 and len(password_field_idx) == 1:
                inputs = form.find_all("input", attrs={"name": True})

                url = self.make_absolute(form.attrs.get("action", "").strip() or self.url)
                method = form.attrs.get("method", "GET").strip().upper()
                enctype = form.attrs.get("enctype", "application/x-www-form-urlencoded").lower()
                post_params = []
                get_params = []
                if method == "POST":
                    post_params = [[input_data["name"], input_data.get("value", "")] for input_data in inputs]
                else:
                    get_params = [[input_data["name"], input_data.get("value", "")] for input_data in inputs]

                login_form = web.Request(
                    url,
                    method=method,
                    post_params=post_params,
                    get_params=get_params,
                    encoding=self.apparent_encoding,
                    referer=self.url,
                    enctype=enctype,
                )

                return login_form, username_field_idx[0], password_field_idx[0]

        return None, "", ""
