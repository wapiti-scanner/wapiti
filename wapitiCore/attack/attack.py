#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2008-2023 Nicolas Surribas
# Copyright (C) 2022-2024 Cyberwatch
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
import dataclasses
import os
from os.path import splitext, join as path_join
from urllib.parse import quote, urlparse
from collections import defaultdict
from enum import Enum, Flag, auto
import random
from binascii import hexlify
from typing import Optional, Iterator, Tuple, List, Callable, Union, Iterable, Type
from asyncio import Event
import json

from pkg_resources import resource_filename
from httpx import ReadTimeout, RequestError

from wapitiCore.definitions import FindingBase
from wapitiCore.model import PayloadInfo
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.language.vulnerability import CRITICAL_LEVEL, HIGH_LEVEL, MEDIUM_LEVEL, LOW_LEVEL, INFO_LEVEL
from wapitiCore.net.response import Response
from wapitiCore.net.sql_persister import SqlPersister
from wapitiCore.net import Request
from wapitiCore.mutation.json_mutator import get_item, set_item, find_injectable

all_modules = {
    "backup",
    "brute_login_form",
    "buster",
    "cookieflags",
    "crlf",
    "cms",
    "csp",
    "csrf",
    "exec",
    "file",
    "htaccess",
    "htp",
    "http_headers",
    "https_redirect",
    "ldap",
    "log4shell",
    "methods",
    "network_device",
    "nikto",
    "permanentxss",
    "redirect",
    "shellshock",
    "spring4shell",
    "sql",
    "ssl",
    "ssrf",
    "takeover",
    "timesql",
    "upload",
    "wapp",
    "wp_enum",
    "xss",
    "xxe"
}

# Modules that will be used if option -m isn't used
common_modules = {
    "cookieflags",
    "csp",
    "exec",
    "file",
    "http_headers",
    "permanentxss",
    "redirect",
    "sql",
    "ssl",
    "ssrf",
    "upload",
    "xss"
}

# Modules that will be used in passive mode -m passive
passive_modules = {
    "cookieflags",
    "csp",
    "http_headers",
    "wapp"
}

presets = {
    "all": all_modules,
    "common": common_modules,
    "passive": passive_modules
}

VULN = "vulnerability"
ANOM = "anomaly"
ADDITION = "additional"

# File extensions to attempt to upload for XXE
XXE_FILE_EXTENSIONS = ("svg", "xml")


class PayloadType(Enum):
    pattern = 1
    time = 2
    get = 3
    post = 4
    file = 5
    xss_closing_tag = 6
    xss_non_closing_tag = 7


class ParameterSituation(Flag):
    QUERY_STRING = auto()
    POST_BODY = auto()
    MULTIPART = auto()
    HEADERS = auto()
    JSON_BODY = auto()


@dataclasses.dataclass
class Parameter:
    name: str
    situation: ParameterSituation
    reversed_parameter: bool = False

    @property
    def is_qs_injection(self) -> bool:
        return not self.name and self.situation == ParameterSituation.QUERY_STRING

    @property
    def display_name(self) -> str:
        return "QUERY_STRING" if self.is_qs_injection else self.name


PayloadCallback = Callable[[Optional[Request], Optional[Parameter]], Iterable[PayloadInfo]]
PayloadSource = Union[List[PayloadInfo], PayloadCallback]

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


def random_string(prefix: str = "w", length: int = 10) -> str:
    """Create a random unique ID that will be used to test injection."""
    # doesn't uppercase letters as BeautifulSoup make some data lowercase
    code = prefix + "".join(
        [random.choice("0123456789abcdefghjijklmnopqrstuvwxyz") for __ in range(0, length - len(prefix))]
    )
    return code


def random_string_with_flags():
    return random_string()


class Attack:
    """This class represents an attack, it must be extended	for any class which implements a new type of attack"""

    name = "attack"

    do_get = True
    do_post = True

    # List of modules (strings) that must be launched before the current module
    # Must be defined in the code of the module
    require = []

    DATA_DIR = resource_filename("wapitiCore", os.path.join("data", "attacks"))
    HOME_DIR = os.getenv("HOME") or os.getenv("USERPROFILE") or "home"

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

    @staticmethod
    def get_resource(resource_path: str):
        return resource_filename("wapitiCore", path_join("data", "attacks", resource_path))

    def __init__(
            self,
            crawler: AsyncCrawler,
            persister: SqlPersister,
            attack_options: dict,
            stop_event: Event,
            crawler_configuration: CrawlerConfiguration):
        super().__init__()
        self._session_id = "".join([random.choice("0123456789abcdefghjijklmnopqrstuvwxyz") for __ in range(0, 6)])
        self.crawler = crawler
        self.persister = persister
        self._stop_event = stop_event
        self.options = attack_options
        self.crawler_configuration = crawler_configuration
        self.start = 0

        # List of attack urls already launched in the current module
        self.attacked_get = []
        self.attacked_post = []
        self.network_errors = 0

        self.finished = False

        # List of modules (objects) that must be launched before the current module
        # Must be left empty in the code
        self.deps = []

    async def add_payload(self, finding_class: Type[FindingBase], request_id: int = -1,
                          level: int = 0, request: Request = None, parameter: str = "", info: str = "",
                          response: Response = None):
        await self.persister.add_payload(
            request_id=request_id,
            payload_type=finding_class.type(),
            module=self.name,
            category=finding_class.name(),
            level=level,
            request=request,
            parameter=parameter,
            info=info,
            wstg=finding_class.wstg_code(),
            response=response
        )

    # Define explicit wrapper functions for each severity level
    async def add_info(self, finding_class: Type[FindingBase], request_id: int = -1,
                       request: Optional[Request] = None, parameter: str = "",
                       info: str = "", response: Optional[Response] = None):
        await self.add_payload(finding_class, request_id, INFO_LEVEL, request, parameter, info, response)

    async def add_low(self, finding_class: Type[FindingBase], request_id: int = -1,
                      request: Optional[Request] = None, parameter: str = "",
                      info: str = "", response: Optional[Response] = None):
        await self.add_payload(finding_class, request_id, LOW_LEVEL, request, parameter, info, response)

    async def add_medium(self, finding_class: Type[FindingBase], request_id: int = -1,
                         request: Optional[Request] = None, parameter: str = "",
                         info: str = "", response: Optional[Response] = None):
        await self.add_payload(finding_class, request_id, MEDIUM_LEVEL, request, parameter, info, response)

    async def add_high(self, finding_class: Type[FindingBase], request_id: int = -1,
                       request: Optional[Request] = None, parameter: str = "",
                       info: str = "", response: Optional[Response] = None):
        await self.add_payload(finding_class, request_id, HIGH_LEVEL, request, parameter, info, response)

    async def add_critical(self, finding_class: Type[FindingBase], request_id: int = -1,
                           request: Optional[Request] = None, parameter: str = "",
                           info: str = "", response: Optional[Response] = None):
        await self.add_payload(finding_class, request_id, CRITICAL_LEVEL, request, parameter, info, response)

    def load_require(self, dependencies: list = None):
        self.deps = dependencies

    @property
    def attack_level(self):
        return self.options.get("level", 1)

    @property
    def dns_endpoint(self):
        return self.options.get("dns_endpoint", "dns.wapiti3.ovh")

    @property
    def internal_endpoint(self):
        return self.options.get("internal_endpoint", "https://wapiti3.ovh/")

    @property
    def external_endpoint(self):
        return self.options.get("external_endpoint", "http://wapiti3.ovh/")

    @property
    def max_attack_time(self):
        return self.options.get("max_attack_time", None)

    @property
    def cms(self):
        return self.options.get("cms", "drupal,joomla,prestashop,spip,wp")

    @property
    def wapp_url(self):
        return self.options.get("wapp_url", "https://raw.githubusercontent.com/wapiti-scanner/wappalyzerfork/main/")

    @property
    def wapp_dir(self):
        return self.options.get("wapp_dir", None)

    @property
    def proto_endpoint(self):
        parts = urlparse(self.external_endpoint)
        return parts.netloc + parts.path

    async def must_attack(
            self,
            request: Request,  # pylint: disable=unused-argument
            response: Optional[Response] = None,  # pylint: disable=unused-argument
    ):
        if response.is_directory_redirection:
            return False

        return not self.finished

    @property
    def must_attack_query_string(self):
        return self.attack_level == 2

    async def attack(self, request: Request, response: Optional[Response] = None):
        raise NotImplementedError("Override me bro")

    def get_mutator(self):
        methods = ""
        if self.do_get:
            methods += "G"
        if self.do_post:
            methods += "PF"

        return Mutator(
            methods=methods,
            qs_inject=self.must_attack_query_string,
            skip=self.options.get("skipped_parameters"),
            module=self.name
        )

    async def does_timeout(self, request, timeout: float = None):
        try:
            await self.crawler.async_send(request, timeout=timeout)
        except ReadTimeout:
            return True
        except RequestError:
            pass
        return False


class Mutator:
    def __init__(
            self, methods="FGP", qs_inject=False, max_queries_per_pattern: int = 1000,
            parameters=None,  # Restrict attack to a whitelist of parameters
            skip=None,  # Must not attack those parameters (blacklist)
            module=None
    ):
        self._mutate_get = "G" in methods.upper()
        self._mutate_file = "F" in methods.upper()
        self._mutate_post = "P" in methods.upper()
        self._qs_inject = qs_inject
        self._attacks_per_url_pattern = defaultdict(int)
        self._max_queries_per_pattern = max_queries_per_pattern
        self._parameters = parameters if isinstance(parameters, list) else []
        self._skip_list = skip if isinstance(skip, set) else set()
        self._attack_hashes = set()
        self._json_attack_hashes = set()
        self._skip_list.update(COMMON_ANNOYING_PARAMETERS)
        self._module = module

    def _mutate_urlencoded_multipart(
            self,
            request: Request,
            payloads: PayloadSource
    ) -> Iterator[Tuple[Request, Parameter, PayloadInfo]]:
        get_params = request.get_params
        post_params = request.post_params
        file_params = request.file_params
        referer = request.referer

        # On a JSON body we exclude post and file parameters as it won't work with this mutator
        # still it may be interesting to fuzz the query string
        all_params = [get_params] if request.is_json else [get_params, post_params, file_params]
        for params_list in all_params:
            parameter_situation = None
            if params_list is get_params:
                parameter_situation = ParameterSituation.QUERY_STRING
                if not self._mutate_get:
                    continue
            elif params_list is post_params:
                parameter_situation = ParameterSituation.POST_BODY
                if not self._mutate_post:
                    continue
            elif params_list is file_params:
                parameter_situation = ParameterSituation.MULTIPART
                if not self._mutate_file:
                    continue

            for i, __ in enumerate(params_list):
                param_name = quote(params_list[i][0])

                if self._skip_list and param_name in self._skip_list:
                    continue

                if self._parameters and param_name not in self._parameters:
                    continue

                saved_value = params_list[i][1]
                if saved_value is None:
                    saved_value = ""

                if params_list is file_params:
                    params_list[i][1] = ["__PAYLOAD__", params_list[i][1][1]]  # second entry is file content
                else:
                    params_list[i][1] = "__PAYLOAD__"

                attack_pattern = Request(
                    request.path,
                    method=request.method,
                    get_params=get_params,
                    post_params=post_params,
                    file_params=file_params,
                    enctype=request.enctype,
                )

                if hash(attack_pattern) not in self._attack_hashes:
                    self._attack_hashes.add(hash(attack_pattern))
                    parameter = Parameter(name=param_name, situation=parameter_situation)
                    reverse_parameter = None
                    iterator = payloads if isinstance(payloads, list) else payloads(request, parameter)

                    for payload_info in iterator:
                        raw_payload = payload_info.payload

                        if ("[FILE_NAME]" in raw_payload or "[FILE_NOEXT]" in raw_payload) and not request.file_name:
                            continue

                        # no quoting: send() will do it for us
                        raw_payload = raw_payload.replace("[FILE_NAME]", request.file_name)
                        raw_payload = raw_payload.replace("[FILE_NOEXT]", splitext(request.file_name)[0])

                        if isinstance(request.path_id, int):
                            raw_payload = raw_payload.replace("[PATH_ID]", str(request.path_id))

                        raw_payload = raw_payload.replace(
                            "[PARAM_AS_HEX]",
                            hexlify(param_name.encode("utf-8", errors="replace")).decode()
                        )

                        if params_list is file_params:
                            if "[EXTVALUE]" in raw_payload:
                                if "." not in saved_value[0][:-1]:
                                    # Nothing that looks like an extension, skip the payload
                                    continue
                                raw_payload = raw_payload.replace("[EXTVALUE]", saved_value[0].rsplit(".", 1)[-1])

                            # Injection takes place on the filename here
                            raw_payload = raw_payload.replace("[VALUE]", saved_value[0])
                            raw_payload = raw_payload.replace("[DIRVALUE]", saved_value[0].rsplit('/', 1)[0])
                            params_list[i][1] = (raw_payload, saved_value[1], saved_value[2])
                        else:
                            if "[EXTVALUE]" in raw_payload:
                                if "." not in saved_value[:-1]:
                                    # Nothing that looks like an extension, skip the payload
                                    continue
                                raw_payload = raw_payload.replace("[EXTVALUE]", saved_value.rsplit(".", 1)[-1])

                            raw_payload = raw_payload.replace("[VALUE]", saved_value)
                            raw_payload = raw_payload.replace("[DIRVALUE]", saved_value.rsplit('/', 1)[0])
                            params_list[i][1] = raw_payload

                        evil_req = Request(
                            request.path,
                            method=request.method,
                            get_params=get_params,
                            post_params=post_params,
                            file_params=file_params,
                            referer=referer,
                            link_depth=request.link_depth,
                            enctype=request.enctype,
                        )
                        payload_info.payload = raw_payload
                        yield evil_req, parameter, payload_info

                        if self._module == "exec":
                            reverse_parameter = Parameter(name=payload_info.payload,
                                                          situation=parameter_situation, reversed_parameter=True)
                            reverse_payload_info = payload_info
                            reverse_payload_info.payload = param_name

                            reverse_evil_req = Request(
                                request.path,
                                method=request.method,
                                get_params=get_params+[[reverse_parameter.name, reverse_payload_info.payload]],
                                post_params=post_params+[[reverse_parameter.name, reverse_payload_info.payload]],
                                file_params=file_params,
                                referer=referer,
                                link_depth=request.link_depth,
                                enctype=request.enctype,
                            )
                            yield reverse_evil_req, reverse_parameter, reverse_payload_info

                params_list[i][1] = saved_value

    def _mutate_query_string(
            self,
            request: Request,
            payloads: PayloadSource
    ) -> Iterator[Tuple[Request, Parameter, PayloadInfo]]:
        get_params = request.get_params
        referer = request.referer

        if not get_params and request.method == "GET" and self._qs_inject:
            attack_pattern = Request(
                f"{request.path}?__PAYLOAD__",
                method=request.method,
                referer=referer,
                link_depth=request.link_depth
            )

            if hash(attack_pattern) not in self._attack_hashes:
                self._attack_hashes.add(hash(attack_pattern))
                parameter = Parameter(name="", situation=ParameterSituation.QUERY_STRING)
                iterator = payloads if isinstance(payloads, list) else payloads(request, parameter)

                for payload_info in iterator:
                    raw_payload = payload_info.payload

                    # Ignore payloads reusing existing parameter values
                    if "[VALUE]" in raw_payload:
                        continue

                    if "[DIRVALUE]" in raw_payload:
                        continue

                    if ("[FILE_NAME]" in raw_payload or "[FILE_NOEXT]" in raw_payload) and not request.file_name:
                        continue

                    raw_payload = raw_payload.replace("[FILE_NAME]", request.file_name)
                    raw_payload = raw_payload.replace("[FILE_NOEXT]", splitext(request.file_name)[0])

                    if isinstance(request.path_id, int):
                        raw_payload = raw_payload.replace("[PATH_ID]", str(request.path_id))

                    raw_payload = raw_payload.replace(
                        "[PARAM_AS_HEX]",
                        hexlify(b"QUERY_STRING").decode()
                    )

                    evil_req = Request(
                        f"{request.path}?{quote(raw_payload)}",
                        method=request.method,
                        referer=referer,
                        link_depth=request.link_depth
                    )

                    payload_info.payload = raw_payload
                    yield evil_req, parameter, payload_info

    def _mutate_json(
            self,
            request: Request,
            payloads: PayloadSource
    ) -> Iterator[Tuple[Request, Parameter, PayloadInfo]]:
        try:
            data = json.loads(request.post_params)
        except json.JSONDecodeError:
            return

        get_params = request.get_params
        referer = request.referer

        injection_points = find_injectable([], data)

        for json_path in injection_points:
            saved_value = get_item(data, json_path)
            set_item(data, json_path, "__PAYLOAD__")
            attack_hash = hash(request.url + json.dumps(data))

            if attack_hash in self._json_attack_hashes:
                # restore the object and move to next injection point
                set_item(data, json_path, saved_value)
                continue

            self._json_attack_hashes.add(attack_hash)

            parameter = Parameter(
                name=".".join([str(key) for key in json_path]),
                situation=ParameterSituation.JSON_BODY,
            )
            iterator = payloads if isinstance(payloads, list) else payloads(request, parameter)

            payload_info: PayloadInfo
            for payload_info in iterator:
                raw_payload = payload_info.payload

                # We will inject some payloads matching those keywords whatever the type of the object to overwrite
                if ("[FILE_NAME]" in raw_payload or "[FILE_NOEXT]" in raw_payload) and not request.file_name:
                    continue

                # no quoting: send() will do it for us
                raw_payload = raw_payload.replace("[FILE_NAME]", request.file_name)
                raw_payload = raw_payload.replace("[FILE_NOEXT]", splitext(request.file_name)[0])

                if isinstance(request.path_id, int):
                    raw_payload = raw_payload.replace("[PATH_ID]", str(request.path_id))

                # We don't want to replace certain placeholders reusing the current value if that value is not a string
                if any(pattern in raw_payload for pattern in ("[EXTVALUE]", "[DIRVALUE]")):
                    if not isinstance(saved_value, str):
                        continue

                    if "[EXTVALUE]" in raw_payload:
                        if "." not in saved_value[:-1]:
                            # Nothing that looks like an extension, skip the payload
                            continue
                        raw_payload = raw_payload.replace("[EXTVALUE]", saved_value.rsplit(".", 1)[-1])

                    raw_payload = raw_payload.replace("[DIRVALUE]", saved_value.rsplit('/', 1)[0])

                if "[VALUE]" in raw_payload:
                    if not isinstance(saved_value, (int, str)):
                        continue

                    raw_payload = raw_payload.replace("[VALUE]", str(saved_value))

                set_item(data, json_path, raw_payload)

                evil_req = Request(
                    request.path,
                    method=request.method,
                    enctype="application/json",
                    get_params=get_params,
                    post_params=json.dumps(data),
                    referer=referer,
                    link_depth=request.link_depth
                )
                payload_info.payload = raw_payload
                yield evil_req, parameter, payload_info
                # put back the previous value
                set_item(data, json_path, saved_value)

    def mutate(self,
               request: Request,
               payloads: PayloadSource) -> Iterator[Tuple[Request, Parameter, PayloadInfo]]:

        yield from self._mutate_urlencoded_multipart(request, payloads)
        if request.is_json and self._mutate_post:
            yield from self._mutate_json(request, payloads)

        yield from self._mutate_query_string(request, payloads)


class XXEUploadMutator:
    def __init__(self, parameters=None, skip=None):
        self._attack_hashes = set()
        self._parameters = parameters if isinstance(parameters, list) else []
        self._skip_list = skip if isinstance(skip, set) else set()

    def mutate(self, request: Request, payloads: PayloadSource) -> Iterator[Tuple[Request, Parameter, PayloadInfo]]:
        get_params = request.get_params
        post_params = request.post_params
        referer = request.referer

        for i in range(len(request.file_params)):
            new_params = request.file_params
            param_name = new_params[i][0]

            if self._skip_list and param_name in self._skip_list:
                continue

            if self._parameters and param_name not in self._parameters:
                continue

            parameter = Parameter(name=param_name, situation=ParameterSituation.MULTIPART)
            iterator = payloads if isinstance(payloads, list) else payloads(request, parameter)
            for payload_info in iterator:
                if isinstance(payload_info, str):
                    raw_payload = payload_info
                else:
                    raw_payload = payload_info.payload

                if ("[FILE_NAME]" in raw_payload or "[FILE_NOEXT]" in raw_payload) and not request.file_name:
                    continue

                # no quoting: send() will do it for us
                raw_payload = raw_payload.replace("[FILE_NAME]", request.file_name)
                raw_payload = raw_payload.replace("[FILE_NOEXT]", splitext(request.file_name)[0])

                if isinstance(request.path_id, int):
                    raw_payload = raw_payload.replace("[PATH_ID]", str(request.path_id))

                raw_payload = raw_payload.replace(
                    "[PARAM_AS_HEX]",
                    hexlify(param_name.encode("utf-8", errors="replace")).decode()
                )

                for file_extension in XXE_FILE_EXTENSIONS:
                    # httpx needs bytes as content value
                    new_params[i][1] = (f"content.{file_extension}", raw_payload.encode(errors="replace"), "text/xml")

                    evil_req = Request(
                        request.path,
                        method=request.method,
                        get_params=get_params,
                        post_params=post_params,
                        file_params=new_params,
                        referer=referer,
                        link_depth=request.link_depth
                    )
                    payload_info.payload = raw_payload
                    yield evil_req, parameter, payload_info
