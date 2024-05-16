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
# Standard libraries
import re
from functools import lru_cache
from hashlib import md5
from posixpath import normpath
from urllib.parse import urlparse, urlunparse
from typing import Iterator, List, Optional, Dict, Set, Tuple

from bs4 import BeautifulSoup
from bs4.element import Comment, Doctype, Tag
from tld import get_fld
from tld.exceptions import TldBadUrl, TldDomainNotFound

# Internal libraries
from wapitiCore import parser_name
from wapitiCore.net import Request, make_absolute
from wapitiCore.parsers.javascript import extract_js_redirections

DISCONNECT_REGEX = r'(?i)((log|sign)\s?(out|off)|disconnect|déconnexion)'
CONNECT_ERROR_REGEX = r'(invalid|'\
                      r'authentication failed|'\
                      r'denied|'\
                      r'incorrect|'\
                      r'failed|'\
                      r'not found|'\
                      r'expired|'\
                      r'try again|'\
                      r'captcha|'\
                      r'two-factors|'\
                      r'verify your email|'\
                      r'erreur)'


def not_empty(original_function):
    def wrapped(*args, **kwargs):
        generator = original_function(*args, **kwargs)
        for value in generator:
            if value:
                yield value
    return wrapped


AUTOFILL_VALUES = {
    "checkbox": "default",
    "color": "#bada55",
    "date": "2023-03-03",
    "datetime": "2023-03-03T20:35:34.32",
    "datetime-local": "2023-03-03T22:41",
    "email": "wapiti2021@mailinator.com",
    "file": ("pix.gif", b"GIF89a", "image/gif"),
    "hidden": "default",
    "month": "2023-03",
    "number": "1337",
    "password": "Letm3in_",  # 8 characters with uppercase, digit and special char for common rules
    "radio": "on",
    "range": "37",
    "search": "default",
    "submit": "submit",
    "tel": "0606060606",
    "text": "default",
    "time": "13:37",
    "url": "https://wapiti-scanner.github.io/",
    "username": "alice",
    "week": "2019-W24"
}

# Field types that we should always fill
NON_EMPTY_FIELD_TYPES = (
    "color",  # browsers send them with default value #000000 no matter what
    "range",  # browsers send a value in the middle of the range
    # bellow we consider that if they are present they are meant to be filled
    "date", "datetime", "datetime-local", "month", "time", "week",
)


def is_required(input_field: Tag) -> bool:
    """Returns True if the given input field should be filled"""
    if "required" in input_field.attrs or "checked" in input_field.attrs:
        return True

    if input_field.attrs.get("type", "text").lower() in NON_EMPTY_FIELD_TYPES:
        return True

    return False


def get_input_field_value(input_field: Tag, autofill: bool = False) -> str:
    """Returns the value that we should the field with"""
    # When attribute "type" is missing, it is considered as text type
    input_type = input_field.attrs.get("type", "text").lower()
    # Function should always be used with a field that has a name
    input_name = input_field["name"].lower()
    autofill |= is_required(input_field)
    fallback = input_field.get("value", "")

    # If there is a non-empty default value, use it
    # If it is empty, it is OK if autofill is not set
    if fallback or not autofill:
        return fallback

    # Otherwise use our hardcoded values
    if input_type == "text":
        if "mail" in input_name:
            # If an input text match name "mail" then put a valid email address in it
            return AUTOFILL_VALUES["email"]
        if "pass" in input_name or "pwd" in input_name:
            # Looks like a text field but waiting for a password
            return AUTOFILL_VALUES["password"]
        if "user" in input_name or "login" in input_name:
            return AUTOFILL_VALUES["username"]

    return AUTOFILL_VALUES[input_type]


class Html:
    def __init__(self, text: str, url: str, encoding: str = "utf-8", allow_fragments: bool = False):
        self._content = text
        self._url = url
        self._base = None
        self._soup = BeautifulSoup(self._content, parser_name)
        self._encoding = encoding
        self._allow_fragments = allow_fragments

        try:
            # TODO: httpx.URL is interesting, reuse that
            self._fld = get_fld(url)
        except TldDomainNotFound:
            self._fld = urlparse(url).netloc

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

    @not_empty
    def _scripts(self) -> Iterator[str]:
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
    def soup(self) -> BeautifulSoup:
        """Returns a parsable BeautifulSoup representation of the webpage.

        @rtype: BeautifulSoup
        """
        return self._soup

    async def clean(self):
        if self._soup is not None:
            self._soup.decompose()
            del self._soup

    def _make_absolute(self, url: str) -> str:
        return make_absolute(self._base or self._url, url, allow_fragments=self._allow_fragments)

    @property
    @lru_cache(maxsize=2)
    def scripts(self) -> List[str]:
        """List of URLs of imported JS scripts. Query strings and anchors are removed.

        @rtype: list
        """
        return [self._make_absolute(script_url) for script_url in self._scripts()]

    def iter_frames(self) -> Iterator[str]:
        """Returns the absolute URLs of frames loaded in the webpage."""
        for tag in self.soup.find_all(["frame", "iframe"], src=True):
            value = self._cleanup_fragment(tag["src"]).strip()
            if value:
                fixed_url = self._make_absolute(value)
                if fixed_url:
                    yield fixed_url

    def _cleanup_fragment(self, url: str) -> str:
        if self._allow_fragments:
            return url
        return url.split("#")[0]

    @not_empty
    def _iter_raw_links(self) -> Iterator[str]:
        """Generator returning all raw URLs found in HTML "a href", frame's src tags and redirections."""
        for tag in self.soup.find_all("a", href=True):
            yield self._cleanup_fragment(tag["href"]).strip()

        for tag in self.soup.find_all(["frame", "iframe"], src=True):
            yield self._cleanup_fragment(tag["src"]).strip()

        for tag in self.soup.find_all("form", action=True):
            yield tag["action"]

        for tag in self.soup.find_all("button", formaction=True):
            yield tag["formaction"]

    @not_empty
    def _iter_links(self) -> Iterator[str]:
        """Generator returning all links in the webpage. Beware of duplicates.

        @rtype: generator
        """
        for link in self._iter_raw_links():
            yield self._make_absolute(link)

    @property
    def links(self) -> List[str]:
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
    def title(self) -> str:
        """Returns the content of the title HTML tag"""
        if self.soup.head is not None:
            title = self.soup.head.title
            if title is not None:
                return title.text
        return ""

    @property
    def base_url(self) -> str:
        """Returns the base URL used for links in the webpage or None if not specified"""
        __ = self.soup
        return self._base

    @property
    def metas(self) -> Dict[str, str]:
        """Returns a dictionary of all metas tags with name attribute as the key and content attribute as the value."""
        metas = {}
        if self.soup.head is not None:
            for meta_tag in self.soup.head.find_all("meta", attrs={"name": True, "content": True}, content=True):
                tag_name = meta_tag["name"].lower().strip()
                if tag_name:
                    metas[tag_name] = meta_tag["content"]

        return metas

    @property
    def multi_meta(self) -> List[Tuple[str, str]]:
        """Returns a list of tuples of all metas tags with name attribute as the first element of the tuple and content
           attribute as last element of the tuple. Useful when multiple meta tags have the same name but different
           content.
        """
        metas = []
        if self.soup.head is not None:
            for meta_tag in self.soup.head.find_all("meta", attrs={"name": True, "content": True}):
                tag_name = meta_tag["name"].lower().strip()
                if tag_name:
                    metas.append((tag_name, meta_tag["content"]))

        return metas

    @property
    def description(self) -> str:
        """Returns the content of the meta description tag in the HTML header.

        @rtype: str
        """
        return self.metas.get("description", "")

    @property
    def keywords(self) -> List[str]:
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
    def text_only(self) -> str:
        """Returns the displayed text of a webpage (without HTML tags)"""
        # if "text" in self.type and self.size:
        texts = self.soup.find_all(string=True)

        def is_visible(element):
            if len(element.strip()) == 0:
                return False
            if isinstance(element, (Comment, Doctype)):
                return False
            if element.parent.name in ["style", "script", "head"]:
                return False
            return True

        text = " ".join(filter(is_visible, texts)).replace("\r\n", " ").replace("\n", " ")
        return text

    @property
    def text_only_md5(self) -> str:
        return md5(self.text_only.encode(errors="ignore")).hexdigest()

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

            return self._make_absolute(icon_uri)
        return self._make_absolute("/favicon.ico")

    @property
    def images_urls(self) -> List[str]:
        """Returns a list of full images URLs found in the webpage.

        @rtype: list
        """
        urls = set()
        for image_tag in self.soup.find_all("img", src=True):
            image_rel_url = image_tag["src"]
            if not image_rel_url or image_rel_url.startswith("#"):
                continue

            image_url = self._make_absolute(image_rel_url)
            if image_url:
                urls.add(image_url)
        return list(urls)

    @property
    @not_empty
    def extra_urls(self) -> Iterator[str]:
        # Extract URLs for special tags attributes that may reference any kind of resource.
        # See http://htmlreference.io/
        for tag in self.soup.find_all(["area", "base", "link"], href=True):
            yield self._make_absolute(tag["href"])
        for tag in self.soup.find_all(["audio", "embed", "img", "script", "source", "track", "video"], src=True):
            yield self._make_absolute(tag["src"])
        for tag in self.soup.find_all(["blockquote", "del", "ins", "q"], cite=True):
            yield self._make_absolute(tag["cite"])
        for tag in self.soup.find_all("object", data=True):
            yield self._make_absolute(tag["data"])
        for tag in self.soup.find_all("param", attrs={"name": "movie", "value": True}):
            yield self._make_absolute(tag["value"])
        for tag in self.soup.find_all(["img", "source"], srcset=True):
            for source_desc in tag["srcset"].split(","):
                url = source_desc.strip().split(" ")[0]
                if url:
                    yield self._make_absolute(url)

    @property
    def js_redirections(self) -> List[str]:
        """Returns a list or redirection URLs found in the javascript code of the webpage.

        @rtype: list
        """
        # We search directly in the full webpage, so we will be able to find commented redirections or those in events
        urls = {self._make_absolute(redirection) for redirection in extract_js_redirections(self._content)}
        if "" in urls:
            urls.remove("")

        return list(urls)

    @property
    def html_redirections(self) -> List[str]:
        urls = set()
        for meta_tag in self.soup.find_all("meta", attrs={"content": True, "http-equiv": True}):
            if meta_tag and meta_tag["http-equiv"].lower() == "refresh":
                content_str = meta_tag["content"]
                content_str_length = len(meta_tag["content"])
                url_eq_idx = content_str.lower().find("url=")

                if url_eq_idx >= 0:
                    if content_str[url_eq_idx + 4] in ("\"", "'"):
                        url_eq_idx += 1
                        if content_str.endswith(("\"", "'")):
                            content_str_length -= 1
                    url = content_str[url_eq_idx + 4:content_str_length]
                    if url:
                        urls.add(self._make_absolute(url))
        return [url for url in urls if url]

    @property
    def all_redirections(self) -> Set[str]:
        result = set()
        result.update(self.js_redirections)
        result.update(self.html_redirections)
        return result

    # pylint: disable=too-many-branches
    def iter_forms(self, autofill=True) -> Iterator[Request]:
        """Returns a generator of Request extracted from the Response.

        @rtype: generator
        """
        for form in self.soup.find_all("form"):
            url = self._make_absolute(form.attrs.get("action", "").strip() or self._url)
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
                elif input_type in AUTOFILL_VALUES:
                    if input_type == "file":
                        # With file inputs the content is only sent if the method is POST and enctype multipart
                        # otherwise only the file name is sent.
                        # Having a default value set in HTML for a file input doesn't make sense... force our own.
                        if method == "GET":
                            get_params.append([input_field["name"], "pix.gif"])
                        else:
                            if "multipart" in enctype:
                                file_params.append([input_field["name"], AUTOFILL_VALUES["file"]])
                            else:
                                post_params.append([input_field["name"], "pix.gif"])
                    else:
                        input_value = get_input_field_value(input_field, autofill)
                        if input_type == "radio":
                            # Do not put in forms now, do it at the end
                            radio_inputs[input_field["name"]] = input_value
                        else:
                            if method == "GET":
                                get_params.append([input_field["name"], input_value])
                            else:
                                post_params.append([input_field["name"], input_value])

            # A formaction doesn't need a name
            for input_field in form.find_all("input", attrs={"formaction": True}):
                form_actions.add(self._make_absolute(input_field["formaction"].strip() or self._url))

            for button_field in form.find_all("button"):
                if "name" in button_field.attrs:
                    input_name = button_field["name"]
                    input_value = button_field.get("value", "")
                    if method == "GET":
                        get_params.append([input_name, input_value])
                    else:
                        post_params.append([input_name, input_value])

                if "formaction" in button_field.attrs:
                    # If formaction is empty it basically send to the current URL
                    # which can be different from the defined action attribute on the form...
                    form_actions.add(self._make_absolute(button_field["formaction"].strip() or self._url))

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
            new_form = Request(
                url,
                method=method,
                get_params=get_params,
                post_params=post_params,
                file_params=file_params,
                encoding=self._encoding,
                referer=self._url,
                enctype=enctype
            )
            yield new_form

            # Then if we saw some formaction attribute, raise the form with the given formaction URL
            for url in form_actions:
                new_form = Request(
                    url,
                    method=method,
                    get_params=get_params,
                    post_params=post_params,
                    file_params=file_params,
                    encoding=self._encoding,
                    referer=self._url,
                    enctype=enctype
                )
                yield new_form

    def find_login_form(self) -> Tuple[Optional[Request], int, int]:
        """Returns the login Request extracted from the Response, the username and password fields."""

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

                url = self._make_absolute(form.attrs.get("action", "").strip() or self._url)
                method = form.attrs.get("method", "GET").strip().upper()
                enctype = form.attrs.get("enctype", "application/x-www-form-urlencoded").lower()
                post_params = []
                get_params = []
                if method == "POST":
                    post_params = [[input_data["name"], input_data.get("value", "")] for input_data in inputs]
                else:
                    get_params = [[input_data["name"], input_data.get("value", "")] for input_data in inputs]

                login_form = Request(
                    url,
                    method=method,
                    post_params=post_params,
                    get_params=get_params,
                    encoding=self._encoding,
                    referer=self._url,
                    enctype=enctype,
                )

                return login_form, username_field_idx[0], password_field_idx[0]

        return None, 0, 0

    def extract_disconnect_urls(self) -> List[str]:
        """
        Extract all the disconnect urls on the given page and returns them.
        """
        disconnect_urls = []
        for link in self.links:
            if re.search(DISCONNECT_REGEX, link) is not None:
                disconnect_urls.append(link)
        return disconnect_urls

    def is_logged_in(self) -> bool:
        # If we find logging errors on the page
        if self._soup.find(string=re.compile(CONNECT_ERROR_REGEX)) is not None:
            return False
        # If we find a disconnect button on the page
        return self._soup.find(string=re.compile(DISCONNECT_REGEX)) is not None
