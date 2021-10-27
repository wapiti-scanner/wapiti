#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti.sourceforge.io)
# Copyright (C) 2009-2021 Nicolas Surribas
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
from os.path import splitext
from urllib.parse import urljoin

from httpx import RequestError

from wapitiCore.main.log import log_verbose, log_red
from wapitiCore.attack.attack import Attack, random_string
from wapitiCore.language.vulnerability import _
from wapitiCore.definitions.backup import NAME
from wapitiCore.net.web import Request


class ModuleBackup(Attack):
    """
    Uncover backup files on the web server.
    """

    PAYLOADS_FILE = "backupPayloads.txt"

    name = "backup"

    do_get = False
    do_post = False

    def __init__(self, crawler, persister, attack_options, stop_event):
        super().__init__(crawler, persister, attack_options, stop_event)
        self.false_positive_directories = {}

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

            self.false_positive_directories[request.dir_name] = (response and response.status == 200)

        return self.false_positive_directories[request.dir_name]

    async def must_attack(self, request: Request):
        page = request.path
        headers = request.headers

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

    async def attack(self, request: Request):
        page = request.path

        for payload, __ in self.payloads:
            if self._stop_event.is_set():
                break

            if request.file_name:
                if "[FILE_" not in payload:
                    continue

                payload = payload.replace("[FILE_NAME]", request.file_name)
                payload = payload.replace("[FILE_NOEXT]", splitext(request.file_name)[0])
                url = page.replace(request.file_name, payload)
            else:
                if "[FILE_" in payload:
                    continue

                url = urljoin(request.path, payload)

            log_verbose(f"[¨] {url}")

            self.attacked_get.append(page)
            evil_req = Request(url)

            try:
                response = await self.crawler.async_send(evil_req)
            except RequestError:
                self.network_errors += 1
                continue

            if response and response.status == 200:
                # FIXME: Right now we cannot remove the pylint: disable line because the current I18N system
                # uses the string as a token so we cannot use f string
                # pylint: disable=consider-using-f-string
                log_red(_("Found backup file {}".format(evil_req.url)))

                await self.add_vuln_low(
                    request_id=request.path_id,
                    category=NAME,
                    request=evil_req,
                    info=_("Backup file {0} found for {1}").format(url, page)
                )
