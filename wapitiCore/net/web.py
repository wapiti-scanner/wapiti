#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2008-2023 Nicolas Surribas
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
from copy import deepcopy
import posixpath
import sys
from urllib.parse import urlparse, urlunparse, unquote, quote, urljoin
from typing import Optional, List, Tuple, Union
import re


import httpx

Parameters = Optional[Union[List[List[str]], str]]


def urlencode(query, safe='', encoding=None, errors=None, quote_via=quote) -> str:
    """Encode a dict or sequence of two-element tuples into a URL query string.

    If the query arg is a sequence of two-element tuples, the order of the
    parameters in the output will match the order of parameters in the
    input.
    The components of a query arg may each be either a string or a bytes type.
    The safe, encoding, and errors parameters are passed down to the function
    specified by quote_via (encoding and errors only if a component is a str).
    """

    if hasattr(query, "items"):
        query = query.items()
    else:
        # It's a bother at times that strings and string-like objects are
        # sequences.
        try:
            # non-sequence items should not work with len()
            # non-empty strings will fail this
            if len(query) > 0 and not isinstance(query[0], tuple):
                raise TypeError
            # Zero-length sequences of all types will get here and succeed,
            # but that's a minor nit.  Since the original implementation
            # allowed empty dicts that type of behavior probably should be
            # preserved for consistency
        except TypeError as type_error:
            exception_traceback = sys.exc_info()[2]
            raise TypeError("not a valid non-string sequence "
                            "or mapping object").with_traceback(exception_traceback) from type_error

    key_value_pair = []

    for arg_key, arg_value in query:
        if isinstance(arg_key, bytes):
            arg_key = quote_via(arg_key, safe)
        else:
            arg_key = quote_via(str(arg_key), safe, encoding, errors)

        if arg_value is None:
            key_value_pair.append(arg_key)
        elif isinstance(arg_value, bytes):
            arg_value = quote_via(arg_value, safe)
            key_value_pair.append(arg_key + '=' + arg_value)
        elif isinstance(arg_value, str):
            arg_value = quote_via(arg_value, safe, encoding, errors)
            key_value_pair.append(arg_key + '=' + arg_value)
        else:
            try:
                # Is this a sufficient test for sequence-ness?
                len(arg_value)
            except TypeError:
                # not a sequence
                arg_value = quote_via(str(arg_value), safe, encoding, errors)
                key_value_pair.append(arg_key + '=' + arg_value)
            else:
                # loop over the sequence
                for elt in arg_value:
                    if isinstance(elt, bytes):
                        elt = quote_via(elt, safe)
                    else:
                        elt = quote_via(str(elt), safe, encoding, errors)
                    key_value_pair.append(arg_key + '=' + elt)
    return '&'.join(key_value_pair)


def parse_qsl(
        query_string: str, strict_parsing: bool = False,
        encoding: str = 'utf-8', errors: str = 'replace', max_num_fields: Optional[int] = None
) -> List[Tuple[str, str]]:
    """Parse a query given as a string argument.
        Arguments:
        query_string: percent-encoded query string to be parsed
        strict_parsing: flag indicating what to do with parsing errors. If
            false (the default), errors are silently ignored. If true,
            errors raise a ValueError exception.
        encoding and errors: specify how to decode percent-encoded sequences
            into Unicode characters, as accepted by the bytes.decode() method.
        max_num_fields: int. If set, then throws a ValueError
            if there are more than n fields read by parse_qsl().
        Returns a list, as G-d intended.
    """
    # If max_num_fields is defined then check that the number of fields
    # is less than max_num_fields. This prevents a memory exhaustion DOS
    # attack via post bodies with many fields.
    if max_num_fields is not None:
        num_fields = 1 + query_string.count('&') + query_string.count(';')
        if max_num_fields < num_fields:
            raise ValueError('Max number of fields exceeded')

    pairs = [s2 for s1 in query_string.split('&') for s2 in s1.split(';')]
    result_list = []

    for pair in pairs:
        if not pair and not strict_parsing:
            continue

        name_value = pair.split('=', 1)
        if len(name_value) != 2:
            if strict_parsing:
                raise ValueError(f"bad query field: {pair!r}")
            # Handle case of a control-name with no equal sign
            name_value.append(None)

        name = name_value[0].replace('+', ' ')
        name = unquote(name, encoding=encoding, errors=errors)

        if name_value[1]:
            value = name_value[1].replace('+', ' ')
            value = unquote(value, encoding=encoding, errors=errors)
        else:
            value = name_value[1]

        result_list.append((name, value))
    return result_list


def shell_escape(string: str) -> str:
    string = string.replace('\\', '\\\\')
    string = string.replace('"', '\\"')
    string = string.replace('$', '\\$')
    string = string.replace('!', '\\!')
    string = string.replace('`', '\\`')
    return string


def make_absolute(base: str, url: str, allow_fragments=True) -> str:
    """Convert a relative URL to an absolute one (with scheme, host, path, etc) and use the base href if present.

    @type base: str
    @param base: The base URL

    @type url: str
    @param url: A relative URL.

    @type allow_fragments: bool
    @param allow_fragments: Must be set to True if URLs with anchors must be kept
    @rtype: str
    """
    if not url.strip():
        return ""

    current_url_parts = urlparse(base)
    scheme = current_url_parts.scheme
    domain = current_url_parts.netloc
    path = current_url_parts.path
    params = current_url_parts.params

    try:
        parts = urlparse(url)
    except ValueError:
        # malformed URL, for example "Invalid IPv6 URL" errors due to square brackets
        return ""

    try:
        # urlparse tries to convert port in base10. an error is raised if port is not digits
        port = parts.port
    except ValueError:
        port = None

    if (
            (parts.scheme == "http" and port == 80) or
            (parts.scheme == "https" and port == 443)
    ):
        # Remove the port number if it is not necessary, be careful with IPv6 addresses:
        # don't use parts.hostname as it removes square brackets
        parts = parts._replace(netloc=parts.netloc.rsplit(":", 1)[0])

    query_string = parts.query
    url_path = parts.path or '/'
    url_path = posixpath.normpath(url_path.replace("\\", "/"))
    # Returns an empty string for everything that we don't want to deal with
    absolute_url = ""

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
        if parts.scheme in ('http', 'https'):
            if parts.netloc and parts.netloc != "http:":  # malformed url
                absolute_url = urlunparse((parts.scheme, parts.netloc, url_path, parts.params, query_string, ''))
    elif url.startswith("//"):
        if parts.netloc:
            absolute_url = urlunparse((scheme, parts.netloc, url_path or '/', parts.params, query_string, ''))
    elif url.startswith("/"):
        absolute_url = urlunparse((scheme, domain, url_path, parts.params, query_string, ''))
    elif url.startswith("?"):
        absolute_url = urlunparse((scheme, domain, path, params, query_string, ''))
    elif url.startswith("#"):
        if allow_fragments:
            absolute_url = base + url
        else:
            absolute_url = base
    elif url == "":
        absolute_url = base
    else:
        # relative path to file, subdirectory or parent directory
        current_directory = path if path.endswith("/") else path.rsplit("/", 1)[0] + "/"

        new_path = posixpath.normpath(current_directory + url_path)
        if url_path.endswith('/') and not new_path.endswith('/'):
            new_path += '/'

        absolute_url = urlunparse((scheme, domain, new_path, parts.params, query_string, ''))

    return absolute_url


class Request:
    def __init__(
            self,
            path: str,
            method: str = "",
            get_params: Parameters = None,
            post_params: Parameters = None,
            file_params: list = None,
            encoding: str = "UTF-8",
            enctype: str = "",
            referer: str = "",
            link_depth: int = 0
    ):
        """Create a new Request object.

        Takes the following arguments:
            path : The path of the HTTP resource on the server. It can contain a query string.
            get_params : A list of key/value parameters (each one is a list of two string).
                                      Each string should already be urlencoded in the good encoding format.
            post_params : Same structure as above but specify the parameters sent in the HTTP body.
            file_params : Same as above expect the values are a tuple (filename, file_content).
            encoding : A string specifying the encoding used to send data to this URL.
                                  Don't mistake it with the encoding of the webpage pointed out by the Request.
            referer : The URL from which the current Request was found.
        """
        url_parts = urlparse(path)
        try:
            # urlparse tries to convert port in base10. an error is raised if port is not digits
            port = url_parts.port
        except ValueError:
            port = None

        if (
                (url_parts.scheme == "http" and port == 80) or
                (url_parts.scheme == "https" and port == 443)
        ):
            # Remove the port number if it is not necessary
            url_parts = url_parts._replace(netloc=url_parts.netloc.rsplit(":", 1)[0])

        self._resource_path = urlunparse((url_parts.scheme, url_parts.netloc, url_parts.path, url_parts.params, '', ''))
        self._fragment = url_parts.fragment or ""

        # Most of the members of a Request object are immutable so we compute
        # the data only one time (when asked for) and we keep it in memory for less
        # calculations in those "cached" vars.
        self._cached_url = ""
        self._cached_get_keys = None
        self._cached_post_keys = None
        self._cached_file_keys = None
        self._cached_encoded_params = None
        self._cached_encoded_data = None
        self._cached_encoded_files = None
        self._cached_hash = None

        self._cached_hash_params = None
        self._status = None
        self._cookies = None

        if not method:
            # For lazy
            if post_params or file_params:
                self._method = "POST"
            else:
                self._method = "GET"
        else:
            self._method = method

        self._enctype = ""
        if self._method in ["POST", "PUT", "PATCH"]:
            if enctype:
                self._enctype = enctype.lower().strip()
            else:
                if file_params:
                    self._enctype = "multipart/form-data"
                else:
                    self._enctype = "application/x-www-form-urlencoded"

        # same structure as _get_params, see below
        if not post_params:
            # None or empty string or empty list
            self._post_params = []
        else:
            if isinstance(post_params, list):
                # Non-empty list
                self._post_params = deepcopy(post_params)
            elif isinstance(post_params, str):
                if "urlencoded" in self.enctype or self.is_multipart:
                    # special case of multipart is dealt when sending request
                    self._post_params = []
                    if post_params:
                        for post_param in post_params.split("&"):
                            if post_param.find("=") > 0:
                                self._post_params.append(post_param.split("=", 1))
                            else:
                                # ?param without value
                                self._post_params.append([post_param, None])
                else:
                    # must be something like application/json or text/xml
                    self._post_params = post_params

        # eg: files = [['file_field', ('file_name', 'file_content')]]
        if not file_params:
            self._file_params = []
        else:
            if isinstance(file_params, list):
                self._file_params = deepcopy(file_params)
            else:
                self._file_params = file_params

        # eg: get = [['id', '25'], ['color', 'green']]
        if not get_params:
            self._get_params = []
            if url_parts.query:
                self._get_params = [[k, v] for k, v in parse_qsl(url_parts.query)]
        else:
            if isinstance(get_params, list):
                self._get_params = deepcopy(get_params)
            else:
                self._get_params = get_params

        self._encoding = encoding
        self._referer = referer
        self._link_depth = link_depth
        # parsed = urlparse(self._resource_path)
        self._file_path = url_parts.path
        self._hostname = url_parts.hostname
        self._scheme = url_parts.scheme or ""
        self._netloc = url_parts.netloc

        self._port = 80
        if port is not None:
            self._port = port
        elif url_parts.scheme == "https":
            self._port = 443
        self._headers = None
        self._response_content = None
        self._start_time = None
        self._size = 0
        self._path_id = None

    # TODO: hashable objects should be read-only. Currently the Mutator get a deepcopy of params to play with but
    # having read-only params in Request class would be more Pythonic. More work on the Mutator in a future version ?
    def __hash__(self):
        if self._cached_hash is None:
            get_kv = tuple([tuple(param) for param in self._get_params])
            if isinstance(self._post_params, list):
                post_kv = tuple([tuple(param) for param in self._post_params])
            else:
                post_kv = self._enctype + str(len(self._post_params))
            file_kv = tuple([tuple([param[0], param[1][0]]) for param in self._file_params])

            self._cached_hash = hash((self._method, self._resource_path, get_kv, post_kv, file_kv))
        return self._cached_hash

    def __eq__(self, other):
        if not isinstance(other, Request):
            return NotImplemented

        if self._method != other.method:
            return False

        if self._resource_path != other.path:
            return False

        if self._fragment != other.fragment:
            return False

        return hash(self) == hash(other)

    def __lt__(self, other):
        if not isinstance(other, Request):
            return NotImplemented
        if self.url < other.url:
            return True

        if self.url == other.url:
            return self.encoded_data < other.encoded_data
        return False

    def __le__(self, other):
        if not isinstance(other, Request):
            return NotImplemented
        if self.url < other.url:
            return True
        if self.url == other.url:
            return self.encoded_data <= other.encoded_data
        return False

    def __ne__(self, other):
        if not isinstance(other, Request):
            return NotImplemented

        if self.method != other.method:
            return True

        if self._resource_path != other.path:
            return True

        return hash(self) != hash(other)

    def __gt__(self, other):
        if not isinstance(other, Request):
            return NotImplemented
        if self.url > other.url:
            return True
        if self.url == other.url:
            return self.encoded_data > other.encoded_data
        return False

    def __ge__(self, other):
        if not isinstance(other, Request):
            return NotImplemented
        if self.url > other.url:
            return True
        if self.url == other.url:
            return self.encoded_data >= other.encoded_data
        return False

    @property
    def parameters_count(self) -> int:
        if isinstance(self._post_params, list):
            return len(self.get_params) + len(self._post_params) + len(self._file_params)

        return len(self.get_params) + len(self._file_params)

    @staticmethod
    def _encoded_keys(params) -> str:
        return "&".join([quote(key, safe='%') for key in sorted(kv[0] for kv in params)])

    def __repr__(self):
        if self._get_params:
            buff = f"{self._method} {self.url} ({self._link_depth})"
        else:
            buff = f"{self._method} {self._resource_path} ({self._link_depth})"

        if self._post_params:
            buff += "\n\tdata: " + self.encoded_data.replace("\n", "\n\t")
        if self._file_params:
            buff += "\n\tfiles: " + self.encoded_files

        return buff

    def http_repr(self, left_margin: str = "    ") -> str:
        rel_url = self.url.split('/', 3)[3]
        http_string = f"{left_margin}{self._method} /{rel_url} HTTP/1.1\n"

        if self._headers:
            for header_name, header_value in self._headers.items():
                http_string += f"{left_margin}{header_name}: {header_value}\n"

        if self.is_multipart:
            boundary = "------------------------boundarystring"
            http_string += f"{left_margin}Content-Type: multipart/form-data; boundary={boundary}\n\n"
            for field_name, field_value in self._post_params:
                http_string += (
                    f"{left_margin}{boundary}\n{left_margin}Content-Disposition: form-data; "
                    f"name=\"{field_name}\"\n\n{left_margin}{field_value}\n"
                )
            for field_name, field_value in self._file_params:
                http_string += (
                    f"{left_margin}{boundary}\n{left_margin}Content-Disposition: form-data; "
                    f"name=\"{field_name}\"; filename=\"{field_value[0]}\"\n\n{left_margin}" +
                    (field_value[1].decode(errors="replace").replace("\n", "\n" + left_margin).strip()) +
                    "\n"
                )
            http_string += f"{left_margin}{boundary}--\n"
        elif self._post_params:
            if "urlencoded" in self.enctype:
                http_string += f"{left_margin}Content-Type: application/x-www-form-urlencoded\n"
                http_string += f"\n{left_margin}{self.encoded_data}"
            else:
                http_string += f"{left_margin}Content-Type: {self.enctype}\n"
                http_string += "\n" + left_margin + self.encoded_data.replace("\n", "\n" + left_margin).strip()

        return http_string.rstrip()

    @property
    def curl_repr(self) -> str:
        curl_string = f"curl \"{shell_escape(self.url)}\""
        if self._referer:
            curl_string += f" -e \"{shell_escape(self._referer)}\""

        if self.is_multipart:
            # POST with multipart
            for field_name, field_value in self._post_params:
                curl_string += f" -F \"{shell_escape(f'{field_name}={field_value}')}\""
            for field_name, field_value in self._file_params:
                curl_upload_kv = f"{field_name}=@your_local_file;filename={field_value[0]}"
                curl_string += f" -F \"{shell_escape(curl_upload_kv)}\""
        elif self._post_params:
            # POST either urlencoded
            if "urlencoded" in self._enctype:
                curl_string += f" -d \"{shell_escape(self.encoded_data)}\""
            else:
                # Or raw blob
                curl_string += f" -H \"Content-Type: {self._enctype}\" -d @payload_file"

        return curl_string

    @property
    def headers(self) -> httpx.Headers:
        return self._headers

    def set_headers(self, sent_headers: httpx.Headers):
        """Set the sent HTTP headers while requesting the resource"""
        self._headers = sent_headers

    @property
    def response_content(self) -> str:
        return self._response_content

    def set_response_content(self, content: str):
        self._response_content = content

    @property
    def cookies(self):
        return self._cookies

    def set_cookies(self, cookies):
        self._cookies = cookies

    @property
    def size(self) -> int:
        return self._size

    @size.setter
    def size(self, value: int):
        self._size = value

    @property
    def url(self) -> str:
        if not self._cached_url:
            if self._get_params:
                self._cached_url = f"{self._resource_path}?{self._encode_params(self._get_params)}"
            else:
                self._cached_url = self._resource_path
        return self._cached_url

    @property
    def fragment(self) -> str:
        return self._fragment

    @property
    def url_with_fragment(self) -> str:
        if self._fragment:
            return f"{self.url}#{self._fragment}"
        return self.url

    @property
    def hostname(self) -> str:
        return self._hostname

    @property
    def netloc(self) -> str:
        return self._netloc

    @property
    def scheme(self) -> str:
        return self._scheme.lower()

    @property
    def port(self) -> int:
        return self._port

    @property
    def path(self) -> str:
        return self._resource_path

    @property
    def file_path(self) -> str:
        return self._file_path

    @property
    def is_root(self) -> bool:
        return self._file_path == "/"

    @property
    def root(self) -> str:
        return urljoin(self.path, "/")

    @property
    def file_ext(self) -> str:
        return posixpath.splitext(self._file_path)[1].lower()

    @property
    def file_name(self) -> str:
        return posixpath.basename(self._file_path)

    @property
    def dir_name(self) -> str:
        if self.file_name:
            return posixpath.dirname(self._resource_path) + "/"
        return self._resource_path

    @property
    def is_directory(self) -> bool:
        return self.path.endswith("/")

    @property
    def parent_dir(self) -> str:
        if self.file_name:
            return posixpath.dirname(self._resource_path) + "/"
        if self.is_root:
            return self._resource_path
        return posixpath.dirname(posixpath.dirname(self._resource_path)) + "/"

    @property
    def method(self) -> str:
        return self._method

    @property
    def encoding(self) -> str:
        return self._encoding

    @property
    def enctype(self) -> str:
        return self._enctype

    @property
    def is_multipart(self) -> bool:
        return "multipart" in self._enctype

    @property
    def is_json(self) -> bool:
        return self._enctype == "application/json"

    @property
    def referer(self) -> str:
        return self._referer

    @property
    def link_depth(self) -> int:
        return self._link_depth

    @link_depth.setter
    def link_depth(self, value: int):
        self._link_depth = value

    # To prevent errors, always return a deepcopy of the internal lists
    @property
    def get_params(self):
        # Return a list of lists containing two elements (parameter name and parameter value)
        return deepcopy(self._get_params)

    @property
    def post_params(self):
        if isinstance(self._post_params, list):
            return deepcopy(self._post_params)
        return self._post_params

    @property
    def file_params(self):
        return deepcopy(self._file_params)

    @property
    def get_keys(self):
        if self._get_params:
            return list(zip(*self._get_params))[0]
        return ()

    @property
    def post_keys(self):
        if isinstance(self._post_params, list) and self._post_params:
            return list(zip(*self._post_params))[0]
        return ()

    @property
    def file_keys(self):
        if self._file_params:
            return list(zip(*self._file_params))[0]
        return ()

    @staticmethod
    def _encode_params(params) -> str:
        if not params:
            return ""

        if not isinstance(params, list):
            return params

        key_values = []
        for param_key, param_value in params:
            if isinstance(param_value, (tuple, list)):
                key_values.append((param_key, param_value[0]))
            else:
                # May be empty string or None but will be processed differently by our own urlencode()
                key_values.append((param_key, param_value))

        return urlencode(key_values)

    @property
    def encoded_params(self) -> str:
        return self._encode_params(self._get_params)

    @property
    def encoded_data(self) -> str:
        """Return a raw string of key/value parameters for POST requests"""
        return self._encode_params(self._post_params)

    @property
    def encoded_files(self) -> str:
        return self._encode_params(self._file_params)

    @property
    def encoded_get_keys(self) -> str:
        if self._cached_get_keys is None:
            self._cached_get_keys = self._encoded_keys(self._get_params)
        return self._cached_get_keys

    @property
    def encoded_post_keys(self):
        if self._cached_post_keys is None and "urlencoded" in self.enctype:
            self._cached_post_keys = self._encoded_keys(self._post_params)
        return self._cached_post_keys

    @property
    def encoded_file_keys(self) -> str:
        if self._cached_file_keys is None:
            self._cached_file_keys = self._encoded_keys(self._file_params)
        return self._cached_file_keys

    @property
    def encoded_keys(self) -> str:
        return f"{self.encoded_get_keys}|{self.encoded_post_keys}|{self.encoded_file_keys}"

    @property
    def pattern(self) -> str:
        return f"{self.path}?{self.encoded_keys}"

    @property
    def hash_params(self):
        if self._cached_hash_params is None:
            self._cached_hash_params = hash(self.pattern)
        return self._cached_hash_params

    @property
    def path_id(self) -> int:
        return self._path_id

    @path_id.setter
    def path_id(self, value: int):
        self._path_id = value
