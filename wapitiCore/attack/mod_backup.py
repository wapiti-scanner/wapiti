#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2009-2023 Nicolas Surribas
#
# Original authors :
# Anthony DUBOCAGE
# Guillaume TRANCHANT
# Gregory FONTAINE
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
from os.path import splitext, join as path_join
from urllib.parse import urljoin
from typing import Optional, Iterator

from httpx import RequestError

from wapitiCore.main.log import log_verbose, log_red
from wapitiCore.attack.attack import Attack, random_string, Parameter
from wapitiCore.definitions.backup import BackupFinding
from wapitiCore.model import PayloadInfo
from wapitiCore.net import Request, Response
from wapitiCore.parsers.txt_payload_parser import TxtPayloadReader


class ModuleBackup(Attack):
    """
    Uncover backup files on the web server.
    """
    name = "backup"

    do_get = True
    do_post = False

    def __init__(self, crawler, persister, attack_options, stop_event, crawler_configuration):
        super().__init__(crawler, persister, attack_options, stop_event, crawler_configuration)
        self.false_positive_directories = {}

    def get_payloads(self, _: Optional[Request] = None, __: Optional[Parameter] = None) -> Iterator[PayloadInfo]:
        """Load the payloads from the specified file"""
        payload_reader = TxtPayloadReader(path_join(self.DATA_DIR, "backupPayloads.txt"))
        yield from payload_reader

    async def is_false_positive(self, request: Request):
        # Check for false positives by asking an improbable file inside the same folder
        # Use a dict to cache state for each directory
        if request.dir_name not in self.false_positive_directories:
            request = Request(urljoin(request.dir_name, random_string() + ".zip"))
            try:
                response = await self.crawler.async_send(request)
            except RequestError:
                self.network_errors += 1
                # Do not put anything in false_positive_directories, another luck for next time
                return False

            self.false_positive_directories[request.dir_name] = (response and response.is_success)

        return self.false_positive_directories[request.dir_name]

    async def must_attack(self, request: Request, response: Optional[Response] = None):
        page = request.path
        headers = response.headers

        if response.is_directory_redirection:
            return False

        if page in self.attacked_get:
            return False

        # Do not attack application-type files
        if "content-type" not in headers:
            # Sometimes there's no content-type... so we rely on the document extension
            if (page.split(".")[-1] not in self.allowed) and page[-1] != "/":
                return False
        elif "text" not in headers["content-type"]:
            return False

        return not await self.is_false_positive(request)

    async def attack(self, request: Request, response: Optional[Response] = None):
        page = request.path

        for payload_info in self.get_payloads():
            raw_payload = payload_info.payload
            if self._stop_event.is_set():
                break

            if request.file_name:
                if "[FILE_" not in raw_payload:
                    continue

                raw_payload = raw_payload.replace("[FILE_NAME]", request.file_name)
                raw_payload = raw_payload.replace("[FILE_NOEXT]", splitext(request.file_name)[0])
                url = page.replace(request.file_name, raw_payload)
            else:
                if "[FILE_" in raw_payload:
                    continue

                url = urljoin(request.path, raw_payload)

            log_verbose(f"[¨] {url}")

            self.attacked_get.append(page)
            evil_req = Request(url)

            try:
                response = await self.crawler.async_send(evil_req)
            except RequestError:
                self.network_errors += 1
                continue

            if response and response.is_success:
                log_red(f"Found backup file {evil_req.url}")

                await self.add_low(
                    request_id=request.path_id,
                    finding_class=BackupFinding,
                    request=evil_req,
                    info=f"Backup file {url} found for {page}",
                    response=response
                )
