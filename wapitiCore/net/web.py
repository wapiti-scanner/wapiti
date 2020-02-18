#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (http://wapiti.sourceforge.io)
# Copyright (C) 2008-2020 Nicolas Surribas
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
from urllib.parse import urlparse, quote_plus, unquote, quote
import posixpath
from copy import deepcopy
import sys


def urlencode(query, safe='', encoding=None, errors=None, quote_via=quote_plus):
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
            if len(query) and not isinstance(query[0], tuple):
                raise TypeError
            # Zero-length sequences of all types will get here and succeed,
            # but that's a minor nit.  Since the original implementation
            # allowed empty dicts that type of behavior probably should be
            # preserved for consistency
        except TypeError:
            ty, va, tb = sys.exc_info()
            raise TypeError("not a valid non-string sequence "
                            "or mapping object").with_traceback(tb)

    key_value_pair = []

    for k, v in query:
        if isinstance(k, bytes):
            k = quote_via(k, safe)
        else:
            k = quote_via(str(k), safe, encoding, errors)

        if v is None:
            key_value_pair.append(k)
        elif isinstance(v, bytes):
            v = quote_via(v, safe)
            key_value_pair.append(k + '=' + v)
        elif isinstance(v, str):
            v = quote_via(v, safe, encoding, errors)
            key_value_pair.append(k + '=' + v)
        else:
            try:
                # Is this a sufficient test for sequence-ness?
                x = len(v)
            except TypeError:
                # not a sequence
                v = quote_via(str(v), safe, encoding, errors)
                key_value_pair.append(k + '=' + v)
            else:
                # loop over the sequence
                for elt in v:
                    if isinstance(elt, bytes):
                        elt = quote_via(elt, safe)
                    else:
                        elt = quote_via(str(elt), safe, encoding, errors)
                    key_value_pair.append(k + '=' + elt)
    return '&'.join(key_value_pair)


def parse_qsl(qs, strict_parsing=False, encoding='utf-8', errors='replace', max_num_fields=None):
    """Parse a query given as a string argument.
        Arguments:
        qs: percent-encoded query string to be parsed
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
        num_fields = 1 + qs.count('&') + qs.count(';')
        if max_num_fields < num_fields:
            raise ValueError('Max number of fields exceeded')

    pairs = [s2 for s1 in qs.split('&') for s2 in s1.split(';')]
    r = []

    for name_value in pairs:
        if not name_value and not strict_parsing:
            continue

        nv = name_value.split('=', 1)
        if len(nv) != 2:
            if strict_parsing:
                raise ValueError("bad query field: %r" % (name_value,))
            # Handle case of a control-name with no equal sign
            nv.append(None)

        name = nv[0].replace('+', ' ')
        name = unquote(name, encoding=encoding, errors=errors)

        if nv[1]:
            value = nv[1].replace('+', ' ')
            value = unquote(value, encoding=encoding, errors=errors)
        else:
            value = nv[1]

        r.append((name, value))
    return r


def shell_escape(s: str):
    s = s.replace('\\', '\\\\')
    s = s.replace('"', '\\"')
    s = s.replace('$', '\\$')
    s = s.replace('!', '\\!')
    s = s.replace('`', '\\`')
    return s


class Request:
    def __init__(
            self, path: str, method: str = "",
            get_params: list = None, post_params: list = None, file_params: list = None,
            encoding: str = "UTF-8", enctype: str = "",
            referer: str = "", link_depth: int = 0):
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
        self._resource_path = path.split("#")[0]

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

        if not method:
            # For lazy
            if post_params or file_params:
                self._method = "POST"
            else:
                self._method = "GET"
        else:
            self._method = method

        self._enctype = ""
        if self._method == "POST":
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
                # Non empty list
                self._post_params = deepcopy(post_params)
            elif isinstance(post_params, str):
                if "urlencoded" in self.enctype or self.is_multipart:
                    # special case of multipart is dealt when sending request
                    self._post_params = []
                    if len(post_params):
                        for kv in post_params.split("&"):
                            if kv.find("=") > 0:
                                self._post_params.append(kv.split("=", 1))
                            else:
                                # ?param without value
                                self._post_params.append([kv, None])
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
            if "?" in self._resource_path:
                query_string = urlparse(self._resource_path).query
                self._get_params = [[k, v] for k, v in parse_qsl(query_string)]
                self._resource_path = self._resource_path.split("?")[0]
        else:
            if isinstance(get_params, list):
                self._resource_path = self._resource_path.split("?")[0]
                self._get_params = deepcopy(get_params)
            else:
                self._get_params = get_params

        self._encoding = encoding
        self._referer = referer
        self._link_depth = link_depth
        parsed = urlparse(self._resource_path)
        self._file_path = parsed.path
        self._hostname = parsed.netloc
        self._port = 80
        if parsed.port is not None:
            self._port = parsed.port
        elif parsed.scheme == "https":
            self._port = 443
        self._headers = None
        self._start_time = None
        self._duration = -1
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

        return hash(self) == hash(other)

    def __lt__(self, other):
        if not isinstance(other, Request):
            return NotImplemented
        if self.url < other.url:
            return True
        else:
            if self.url == other.url:
                return self.encoded_data < other.encoded_data
            return False

    def __le__(self, other):
        if not isinstance(other, Request):
            return NotImplemented
        if self.url < other.url:
            return True
        elif self.url == other.url:
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
        elif self.url == other.url:
            return self.encoded_data > other.encoded_data
        return False

    def __ge__(self, other):
        if not isinstance(other, Request):
            return NotImplemented
        if self.url > other.url:
            return True
        elif self.url == other.url:
            return self.encoded_data >= other.encoded_data
        return False

    def __len__(self):
        if isinstance(self._post_params, list):
            return len(self.get_params) + len(self._post_params) + len(self._file_params)
        else:
            return len(self.get_params) + len(self._file_params)

    @staticmethod
    def _encoded_keys(params):
        return "&".join([quote(key, safe='%') for key in sorted(kv[0] for kv in params)])

    def __repr__(self):
        if self._get_params:
            buff = "{0} {1} ({2})".format(self._method, self.url, self._link_depth)
        else:
            buff = "{0} {1} ({2})".format(self._method, self._resource_path, self._link_depth)

        if self._post_params:
            buff += "\n\tdata: {}".format(self.encoded_data.replace("\n", "\n\t"))
        if self._file_params:
            buff += "\n\tfiles: {}".format(self.encoded_files)
        return buff

    def http_repr(self, left_margin="    "):
        rel_url = self.url.split('/', 3)[3]
        http_string = "{3}{0} /{1} HTTP/1.1\n{3}Host: {2}\n".format(
            self._method,
            rel_url,
            self._hostname,
            left_margin
        )

        if self._referer:
            http_string += "{}Referer: {}\n".format(left_margin, self._referer)

        if self._file_params:
            boundary = "------------------------boundarystring"
            http_string += "{}Content-Type: multipart/form-data; boundary={}\n\n".format(left_margin, boundary)
            for field_name, field_value in self._post_params:
                http_string += (
                    "{3}{0}\n{3}Content-Disposition: form-data; "
                    "name=\"{1}\"\n\n{3}{2}\n"
                ).format(boundary, field_name, field_value, left_margin)
            for field_name, field_value in self._file_params:
                http_string += (
                    "{3}{0}\n{3}Content-Disposition: form-data; name=\"{1}\"; filename=\"{2}\"\n\n"
                    "{3}{4}\n"
                ).format(
                    boundary,
                    field_name,
                    field_value[0],
                    left_margin,
                    field_value[1].replace("\n", "\n" + left_margin).strip()
                )
            http_string += "{0}{1}--\n".format(left_margin, boundary)
        elif self._post_params:
            if "urlencoded" in self.enctype:
                http_string += "{}Content-Type: application/x-www-form-urlencoded\n".format(left_margin)
                http_string += "\n{}{}".format(left_margin, self.encoded_data)
            else:
                http_string += "{}Content-Type: {}\n".format(left_margin, self.enctype)
                http_string += "\n{}{}".format(
                    left_margin,
                    self.encoded_data.replace("\n", "\n" + left_margin).strip()
                )

        return http_string.rstrip()

    @property
    def curl_repr(self):
        curl_string = "curl \"{0}\"".format(shell_escape(self.url))
        if self._referer:
            curl_string += " -e \"{0}\"".format(shell_escape(self._referer))

        if self._file_params:
            # POST with multipart
            for field_name, field_value in self._post_params:
                curl_string += " -F \"{0}\"".format(shell_escape("{0}={1}".format(field_name, field_value)))
            for field_name, field_value in self._file_params:
                curl_upload_kv = "{0}=@your_local_file;filename={1}".format(field_name, field_value[0])
                curl_string += " -F \"{0}\"".format(shell_escape(curl_upload_kv))
            pass
        elif self._post_params:
            # POST either urlencoded
            if "urlencoded" in self._enctype:
                curl_string += " -d \"{0}\"".format(shell_escape(self.encoded_data))
            else:
                # Or raw blob
                curl_string += " -H \"Content-Type: {}\" -d @payload_file".format(self._enctype)

        return curl_string

    def set_headers(self, response_headers):
        """Set the HTTP headers received while requesting the resource"""
        self._headers = response_headers

    @property
    def size(self):
        return self._size

    @size.setter
    def size(self, value: int):
        self._size = value

    @property
    def duration(self):
        return self._duration

    @duration.setter
    def duration(self, value: float):
        self._duration = value

    @property
    def status(self) -> int:
        return self._status

    @status.setter
    def status(self, value: int):
        self._status = value

    @property
    def url(self) -> str:
        if not self._cached_url:
            if self._get_params:
                self._cached_url = "{0}?{1}".format(
                    self._resource_path,
                    self._encode_params(self._get_params)
                )
            else:
                self._cached_url = self._resource_path
        return self._cached_url

    @property
    def hostname(self) -> str:
        return self._hostname

    @property
    def port(self):
        return self._port

    @property
    def path(self):
        return self._resource_path

    @property
    def file_path(self):
        return self._file_path

    @property
    def is_root(self) -> bool:
        return True if self._file_path == "/" else False

    @property
    def file_ext(self) -> str:
        return posixpath.splitext(self._file_path)[1].lower()

    @property
    def file_name(self) -> str:
        return posixpath.basename(self._file_path)

    @property
    def dir_name(self):
        if self.file_name:
            return posixpath.dirname(self._resource_path) + "/"
        return self._resource_path

    @property
    def parent_dir(self):
        if self.file_name:
            return posixpath.dirname(self._resource_path) + "/"
        elif self.is_root:
            return self._resource_path
        else:
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
    def headers(self):
        return self._headers

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
        if len(self._get_params):
            return list(zip(*self._get_params))[0]
        return ()

    @property
    def post_keys(self):
        if isinstance(self._post_params, list) and len(self._post_params):
            return list(zip(*self._post_params))[0]
        return ()

    @property
    def file_keys(self):
        if len(self._file_params):
            return list(zip(*self._file_params))[0]
        return ()

    @staticmethod
    def _encode_params(params):
        if not params:
            return ""

        if not isinstance(params, list):
            return params

        key_values = []
        for k, v in params:
            if isinstance(v, tuple) or isinstance(v, list):
                key_values.append((k, v[0]))
            else:
                # May be empty string or None but will be processed differently by our own urlencode()
                key_values.append((k, v))

        return urlencode(key_values)

    @property
    def encoded_params(self):
        return self._encode_params(self._get_params)

    @property
    def encoded_data(self):
        """Return a raw string of key/value parameters for POST requests"""
        return self._encode_params(self._post_params)

    @property
    def encoded_files(self):
        return self._encode_params(self._file_params)

    @property
    def encoded_get_keys(self):
        if self._cached_get_keys is None:
            self._cached_get_keys = self._encoded_keys(self._get_params)
        return self._cached_get_keys

    @property
    def encoded_post_keys(self):
        if self._cached_post_keys is None and "urlencoded" in self.enctype:
            self._cached_post_keys = self._encoded_keys(self._post_params)
        return self._cached_post_keys

    @property
    def encoded_file_keys(self):
        if self._cached_file_keys is None:
            self._cached_file_keys = self._encoded_keys(self._file_params)
        return self._cached_file_keys

    @property
    def encoded_keys(self):
        return "{}|{}|{}".format(self.encoded_get_keys, self.encoded_post_keys, self.encoded_file_keys)

    @property
    def pattern(self):
        return "{}?{}".format(self.path, self.encoded_keys)

    @property
    def hash_params(self):
        if self._cached_hash_params is None:
            self._cached_hash_params = hash(self.pattern)
        return self._cached_hash_params

    @property
    def path_id(self):
        return self._path_id

    @path_id.setter
    def path_id(self, value: int):
        self._path_id = value
