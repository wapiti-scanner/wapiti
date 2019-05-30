#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (http://wapiti.sourceforge.net)
# Copyright (C) 2008-2018 Nicolas Surribas
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
from urllib.parse import urlparse, quote
import posixpath
from copy import deepcopy


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
            encoding: str = "UTF-8", multipart: bool = False, referer: str = "", link_depth: int = 0):
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
        self._multipart = multipart
        self._cached_hash_params = None
        self._status = None

        # same structure as _get_params, see below
        if not post_params:
            # None or empty string or empty list
            self._post_params = []
        else:
            if isinstance(post_params, list):
                # Non empty list
                self._post_params = deepcopy(post_params)
            elif isinstance(post_params, str):
                self._post_params = []
                if len(post_params):
                    for kv in post_params.split("&"):
                        if kv.find("=") > 0:
                            self._post_params.append(kv.split("=", 1))
                        else:
                            # ?param without value
                            self._post_params.append([kv, None])

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
                for kv in query_string.split("&"):
                    if kv.find("=") > 0:
                        self._get_params.append(kv.split("=", 1))
                    else:
                        # ?param without value
                        self._get_params.append([kv, None])
                self._resource_path = self._resource_path.split("?")[0]
        else:
            if isinstance(get_params, list):
                self._resource_path = self._resource_path.split("?")[0]
                self._get_params = deepcopy(get_params)
            else:
                self._get_params = get_params

        if not method:
            # For lazy
            if self._post_params or self._file_params:
                self._method = "POST"
            else:
                self._method = "GET"
        else:
            self._method = method
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
            post_kv = tuple([tuple(param) for param in self._post_params])
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
        return len(self.get_params) + len(self._post_params) + len(self._file_params)

    @staticmethod
    def _encoded_keys(params):
        return "&".join([quote(key, safe='%') for key in sorted(kv[0] for kv in params)])

    def __repr__(self):
        if self._get_params:
            buff = "{0} {1} ({2})".format(self._method, self.url, self._link_depth)
        else:
            buff = "{0} {1} ({2})".format(self._method, self._resource_path, self._link_depth)
        if self._post_params:
            buff += "\n\tdata: {}".format(self.encoded_data)
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
                    "{3}/* snip file content snip */\n").format(boundary, field_name, field_value[0], left_margin)
            http_string += "{0}--\n".format(boundary)
        elif self._post_params:
            http_string += "{}Content-Type: application/x-www-form-urlencoded\n".format(left_margin)
            http_string += "\n{}{}".format(left_margin, self.encoded_data)

        return http_string.rstrip()

    @property
    def curl_repr(self):
        curl_string = "curl \"{0}\"".format(shell_escape(self.url))
        if self._referer:
            curl_string += " -e \"{0}\"".format(shell_escape(self._referer))
        if self._file_params:
            for field_name, field_value in self._post_params:
                curl_string += " -F \"{0}\"".format(shell_escape("{0}={1}".format(field_name, field_value)))
            for field_name, field_value in self._file_params:
                curl_upload_kv = "{0}=@your_local_file;filename={1}".format(field_name, field_value[0])
                curl_string += " -F \"{0}\"".format(shell_escape(curl_upload_kv))
            pass
        elif self._post_params:
            curl_string += " -d \"{0}\"".format(shell_escape(self.encoded_data))

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
    def is_multipart(self) -> bool:
        return self._multipart

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
        return deepcopy(self._post_params)

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
        if len(self._post_params):
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

        key_values = []
        for k, v in params:
            k = quote(k, safe='%')
            if v is None:
                key_values.append(k)
            else:
                if isinstance(v, tuple) or isinstance(v, list):
                    # for upload fields
                    v = v[0]
                v = quote(v, safe='%')
                key_values.append("%s=%s" % (k, v))
        return "&".join(key_values)

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
        if self._cached_post_keys is None:
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


if __name__ == "__main__":
    res1 = Request(
        "http://httpbin.org/post?var1=a&var2=b",
        post_params=[['post1', 'c'], ['post2', 'd']]
    )

    res2 = Request(
        "http://httpbin.org/post?var1=a&var2=z",
        post_params=[['post1', 'c'], ['post2', 'd']]
    )

    res3 = Request(
        "http://httpbin.org/post?var1=a&var2=b",
        post_params=[['post1', 'c'], ['post2', 'z']]
    )

    res4 = Request(
        "http://httpbin.org/post?var1=a&var2=b",
        post_params=[['post1', 'c'], ['post2', 'd']]
    )

    res5 = Request(
        "http://httpbin.org/post?var1=z&var2=b",
        post_params=[['post1', 'c'], ['post2', 'd']]
    )

    res6 = Request(
        "http://httpbin.org/post?var3=z&var2=b",
        post_params=[['post1', 'c'], ['post2', 'd']]
    )

    res7 = Request(
        "http://httpbin.org/post?var1=z&var2=b&var4=e",
        post_params=[['post1', 'c'], ['post2', 'd']]
    )

    res8 = Request(
        "http://httpbin.org/post?var2=d&var1=z",
        post_params=[['post1', 'c'], ['post2', 'd']]
    )

    res10 = Request(
        "http://httpbin.org/post?qs0",
        post_params=[['post1', 'c'], ['post2', 'd']]
    )
    res11 = Request(
        "http://httpbin.org/post?qs1",
        post_params=[['post1', 'c'], ['post2', 'd']]
    )

    res12 = Request(
        "http://httpbin.org/post?qs1",
        post_params=[['post1', 'c'], ['post2', 'd']],
        file_params=[['file1', ['fname1', 'content']], ['file2', ['fname2', 'content']]]
    )

    res13 = Request("https://www.youtube.com/user/OneMinuteSilenceBand/videos")
    res14 = Request("https://www.youtube.com/user/OneMinuteSilenceBand/")
    res15 = Request("https://duckduckgo.com/")
    res16 = Request("https://duckduckgo.com/", post_params=[['q', 'Kung Fury']])
    res17 = Request("http://example.com:8080/dir/?x=3")

    res18 = Request(
        "http://httpbin.org/get?a=1",
        get_params=[['get1', 'c'], ['get2', 'd']]
    )

    assert res1 < res2
    assert res2 > res3
    assert res1 < res3
    assert res1 == res4
    assert hash(res1) == hash(res4)
    res4.link_depth = 5
    assert hash(res1) == hash(res4)
    assert res1 != res2
    assert res2 >= res1
    assert res1 <= res3
    assert res13.file_name == "videos"
    assert res10.path == "http://httpbin.org/post"
    assert res10.file_name == "post"
    assert res10.url == "http://httpbin.org/post?qs0"
    assert res13.parent_dir == res14.url
    assert res15.is_root
    assert res15.parent_dir == res15.url
    assert res13.dir_name == res14.url
    assert res14.dir_name == res14.url
    assert res15.dir_name == res15.url
    assert res15 != res16
    query_list = [res15]
    assert res16 not in query_list
    assert res17.dir_name == "http://example.com:8080/dir/"
    assert res18.url == "http://httpbin.org/get?get1=c&get2=d"
    assert res17.hostname == "example.com:8080"
    assert res1.encoded_get_keys == res8.encoded_get_keys
    assert res17.encoded_get_keys == "x"
    assert res16.encoded_get_keys == ""
    assert len(res12) == 5
    assert res12.encoded_get_keys == "qs1"
    assert res5.hash_params == res8.hash_params
    assert res7.hash_params != res8.hash_params

    print("Tests were successful, now launching representations")
    print("=== Basic representation follows ===")
    print(res1)
    print("=== cURL representation follows ===")
    print(res1.curl_repr)
    print("=== HTTP representation follows ===")
    print(res1.http_repr())
    print("=== POST parameters as an array ===")
    print(res1.post_params)
    print("=== POST keys encoded as string ===")
    print(res1.encoded_post_keys)
    print("=== Upload HTTP representation  ===")
    print(res12.http_repr())
    print("=== Upload basic representation ===")
    print(res12)
    print("=== Upload cURL representation  ===")
    print(res12.curl_repr)
    print("===   HTTP GET keys as a tuple  ===")
    print(res1.get_keys)
    print("===  HTTP POST keys as a tuple  ===")
    print(res1.post_keys)
    print("=== HTTP files keys as a tuple  ===")
    print(res12.file_keys)
    print('')
