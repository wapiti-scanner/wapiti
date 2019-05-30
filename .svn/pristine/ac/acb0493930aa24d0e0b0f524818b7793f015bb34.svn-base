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
import os
import sys
from os.path import splitext, join as path_join
from urllib.parse import quote
from collections import defaultdict
from enum import Enum
from math import ceil
import random
from types import GeneratorType, FunctionType

from wapitiCore.net.web import Request


modules = [
    "mod_crlf",
    "mod_exec",
    "mod_file",
    "mod_sql",
    "mod_xss",
    "mod_backup",
    "mod_htaccess",
    "mod_blindsql",
    "mod_permanentxss",
    "mod_nikto",
    "mod_delay",
    "mod_buster",
    "mod_shellshock",
    "mod_methods",
    "mod_ssrf"
]

commons = ["blindsql", "exec", "file", "permanentxss", "sql", "xss", "ssrf"]


class PayloadType(Enum):
    pattern = 1
    time = 2
    get = 3
    post = 4
    file = 5


COMMON_ANNOYING_PARAMETERS = (
    "__VIEWSTATE",
    "__VIEWSTATEENCRYPTED",
    "__VIEWSTATEGENERATOR",
    "__EVENTARGUMENT",
    "__EVENTTARGET",
    "__EVENTVALIDATION",
    "ASPSESSIONID",
    "ASP.NET_SESSIONID",
    "JSESSIONID",
    "CFID",
    "CFTOKEN"
)


class Attack:
    """This class represents an attack, it must be extended	for any class which implements a new type of attack"""

    name = "attack"

    do_get = True
    do_post = True

    # List of modules (strings) that must be launched before the current module
    # Must be defined in the code of the module
    require = []

    BASE_DIR = os.path.dirname(sys.modules["wapitiCore"].__file__)
    CONFIG_DIR = os.path.join(BASE_DIR, "config", "attacks")
    PAYLOADS_FILE = None

    # Color codes
    STD = "\033[0;0m"
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    ORANGE = "\033[0;33m"
    YELLOW = "\033[1;33m"
    BLUE = "\033[1;34m"
    MAGENTA = "\033[0;35m"
    CYAN = "\033[0;36m"
    GB = "\033[0;30m\033[47m"

    allowed = [
        'php', 'html', 'htm', 'xml', 'xhtml', 'xht', 'xhtm',
        'asp', 'aspx', 'php3', 'php4', 'php5', 'txt', 'shtm',
        'shtml', 'phtm', 'phtml', 'jhtml', 'pl', 'jsp', 'cfm',
        'cfml', 'py'
    ]

    # The priority of the module, from 0 (first) to 10 (last). Default is 5
    PRIORITY = 5

    def __init__(self, crawler, persister, logger, attack_options):
        super().__init__()
        self.crawler = crawler
        self.persister = persister
        self.add_vuln = persister.add_vulnerability
        self.add_anom = persister.add_anomaly
        self.payload_reader = PayloadReader(timeout=attack_options["timeout"])
        self.options = attack_options

        # List of attack urls already launched in the current module
        self.attacked_get = []
        self.attacked_post = []

        self.vulnerable_get = []
        self.vulnerable_post = []

        self.verbose = 0
        self.color = 0

        # List of modules (objects) that must be launched before the current module
        # Must be left empty in the code
        self.deps = []

        self._logger = logger
        self.log = self._logger.log
        self.log_blue = self._logger.log_blue
        self.log_cyan = self._logger.log_cyan
        self.log_green = self._logger.log_green
        self.log_magenta = self._logger.log_magenta
        self.log_orange = self._logger.log_orange
        self.log_red = self._logger.log_red
        self.log_white = self._logger.log_white
        self.log_yellow = self._logger.log_yellow

    def set_verbose(self, verbose):
        self.verbose = verbose

    def set_color(self):
        self.color = 1

    @property
    def payloads(self):
        """Load the payloads from the specified file"""
        if self.PAYLOADS_FILE:
            return self.payload_reader.read_payloads(path_join(self.CONFIG_DIR, self.PAYLOADS_FILE))
        return []

    def load_require(self, dependancies: list = None):
        self.deps = dependancies

    @property
    def attack_level(self):
        return self.options["level"]

    @property
    def must_attack_query_string(self):
        return self.attack_level == 2

    def attack(self):
        raise NotImplementedError("Override me bro")

    def get_mutator(self):
        methods = ""
        if self.do_get:
            methods += "G"
        if self.do_post:
            methods += "PF"

        return Mutator(
            methods=methods,
            payloads=self.payloads,
            qs_inject=self.must_attack_query_string,
            skip=self.options.get("skipped_parameters")
        )


class Mutator:
    def __init__(
            self, methods="FGP", payloads=None, qs_inject=False, max_queries_per_pattern: int = 1000,
            parameters=None,  # Restrict attack to a whitelist of parameters
            skip=None  # Must not attack those parameters (blacklist)
    ):
        self._mutate_get = "G" in methods.upper()
        self._mutate_file = "F" in methods.upper()
        self._mutate_post = "P" in methods.upper()
        self._payloads = payloads
        self._qs_inject = qs_inject
        self._attacks_per_url_pattern = defaultdict(int)
        self._max_queries_per_pattern = max_queries_per_pattern
        self._parameters = parameters if isinstance(parameters, list) else []
        self._skip_list = skip if isinstance(skip, set) else set()
        self._attack_hashes = set()
        self._skip_list.update(COMMON_ANNOYING_PARAMETERS)

    def iter_payloads(self):
        # raise tuples of (payloads, flags)
        if isinstance(self._payloads, tuple):
            yield self._payloads
        elif isinstance(self._payloads, list) or isinstance(self._payloads, GeneratorType):
            yield from self._payloads
        elif isinstance(self._payloads, FunctionType):
            result = self._payloads()
            if isinstance(result, GeneratorType):
                yield from result
            else:
                yield result

    def estimate_requests_count(self, request: Request):
        estimation = len(request) if isinstance(self._payloads, tuple) else len(request) * len(self._payloads)
        if self._qs_inject and request.method == "GET" and len(request) == 0:
            # Injection directly in query string is made only on GET requests with no parameters in URL
            estimation += len(self._payloads)
        return estimation

    def mutate(self, request: Request):
        get_params = request.get_params
        post_params = request.post_params
        file_params = request.file_params
        referer = request.referer

        # estimation = self.estimate_requests_count(request)
        #
        # if self._attacks_per_url_pattern[request.hash_params] + estimation > self._max_queries_per_pattern:
        #     # Otherwise (pattern already attacked), make sure we don't exceed maximum allowed
        #     return
        #
        # self._attacks_per_url_pattern[request.hash_params] += estimation

        for params_list in [get_params, post_params, file_params]:
            for i in range(len(params_list)):
                param_name = quote(params_list[i][0])

                if self._skip_list and param_name in self._skip_list:
                    continue

                if self._parameters and param_name not in self._parameters:
                    continue

                saved_value = params_list[i][1]
                if saved_value is None:
                    saved_value = ""

                if params_list is file_params:
                    params_list[i][1] = ["__PAYLOAD__", params_list[i][1][1]]
                else:
                    params_list[i][1] = "__PAYLOAD__"

                attack_pattern = Request(
                    request.path,
                    method=request.method,
                    get_params=get_params,
                    post_params=post_params,
                    file_params=file_params
                )

                if hash(attack_pattern) not in self._attack_hashes:
                    self._attack_hashes.add(hash(attack_pattern))

                    for payload, original_flags in self.iter_payloads():
                        # no quoting: send() will do it for us
                        payload = payload.replace("[FILE_NAME]", request.file_name)
                        payload = payload.replace("[FILE_NOEXT]", splitext(request.file_name)[0])

                        # Flags from iter_payloads should be considered as mutable (even if it's ot the case)
                        # so let's copy them just to be sure we don't mess with them.
                        flags = set(original_flags)

                        if params_list is file_params:
                            payload = payload.replace("[VALUE]", saved_value[0])
                            payload = payload.replace("[DIRVALUE]", saved_value[0].rsplit('/', 1)[0])
                            params_list[i][1][0] = payload
                            flags.add(PayloadType.file)
                        else:
                            payload = payload.replace("[VALUE]", saved_value)
                            payload = payload.replace("[DIRVALUE]", saved_value.rsplit('/', 1)[0])
                            params_list[i][1] = payload
                            if params_list is get_params:
                                flags.add(PayloadType.get)
                            else:
                                flags.add(PayloadType.post)

                        evil_req = Request(
                            request.path,
                            method=request.method,
                            get_params=get_params,
                            post_params=post_params,
                            file_params=file_params,
                            referer=referer,
                            link_depth=request.link_depth
                        )
                        yield evil_req, param_name, payload, flags

                params_list[i][1] = saved_value

        if not get_params and request.method == "GET" and self._qs_inject:
            attack_pattern = Request(
                "{}?__PAYLOAD__".format(request.path),
                method=request.method,
                referer=referer,
                link_depth=request.link_depth
            )

            if hash(attack_pattern) not in self._attack_hashes:
                self._attack_hashes.add(hash(attack_pattern))

                for payload, original_flags in self.iter_payloads():
                    # Ignore payloads reusing existing parameter values
                    if "[VALUE]" in payload:
                        continue

                    if "[DIRVALUE]" in payload:
                        continue

                    payload = payload.replace("[FILE_NAME]", request.file_name)
                    payload = payload.replace("[FILE_NOEXT]", splitext(request.file_name)[0])
                    flags = set(original_flags)

                    evil_req = Request(
                        "{}?{}".format(request.path, quote(payload)),
                        method=request.method,
                        referer=referer,
                        link_depth=request.link_depth
                    )
                    flags.add(PayloadType.get)

                    yield evil_req, "QUERY_STRING", flags


class PayloadReader:
    """Class for reading and writing in text files"""

    def __init__(self, timeout=20):
        self._timeout = timeout

    def read_payloads(self, filename):
        """returns a array"""
        lines = []
        try:
            # Reminder : don't try to read payload files as UTF-8, must give str type
            with open(filename) as f:
                for line in f:
                    flags = set()
                    clean_line = line.strip(" \n")
                    clean_line = clean_line.replace("[TAB]", "\t")
                    clean_line = clean_line.replace("[LF]", "\n")
                    clean_line = clean_line.replace("[TIME]", str(int(ceil(self._timeout)) + 1))

                    payload_type = PayloadType.pattern
                    if "[TIMEOUT]" in clean_line:
                        payload_type = PayloadType.time
                        clean_line = clean_line.replace("[TIMEOUT]", "")

                    flags.add(payload_type)

                    if clean_line != "":
                        lines.append((clean_line.replace("\\0", "\0"), flags))
        except IOError as exception:
            print(exception)
        return lines


if __name__ == "__main__":

    mutator = Mutator(payloads=[("INJECT", set()), ("ATTACK", set())], qs_inject=True, max_queries_per_pattern=16)
    res1 = Request(
        "http://httpbin.org/post?var1=a&var2=b",
        post_params=[['post1', 'c'], ['post2', 'd']]
    )

    res2 = Request(
        "http://httpbin.org/post?var1=a&var2=z",
        post_params=[['post1', 'c'], ['post2', 'd']]
    )

    res3 = Request(
        "http://httpbin.org/get?login=admin&password=letmein",
    )

    assert res1.hash_params == res2.hash_params

    for evil_request, param_name, payload, flags in mutator.mutate(res1):
        print(evil_request)
        print(flags)

    print('')
    print("#"*50)
    print('')

    for evil_request, param_name, payload, flags in mutator.mutate(res2):
        print(evil_request)

    print('')
    print("#"*50)
    print('')

    def iterator():
        yield ("abc", set())
        yield ("def", set())

    mutator = Mutator(payloads=iterator, qs_inject=True, max_queries_per_pattern=16)
    for evil_request, param_name, payload, flags in mutator.mutate(res3):
        print(evil_request)

    print('')
    print("#"*50)
    print('')

    def random_string():
        """Create a random unique ID that will be used to test injection."""
        # doesn't uppercase letters as BeautifulSoup make some data lowercase
        return "w" + "".join([random.choice("0123456789abcdefghjijklmnopqrstuvwxyz") for __ in range(0, 9)]), set()

    mutator = Mutator(payloads=random_string, qs_inject=True, max_queries_per_pattern=16)
    for evil_request, param_name, payload, flags in mutator.mutate(res3):
        print(evil_request)
        print("Payload is", payload)

    mutator = Mutator(methods="G", payloads=[("INJECT", set()), ("ATTACK", set())], qs_inject=True, parameters=["var1"])
    assert len(list(mutator.mutate(res1))) == 2
