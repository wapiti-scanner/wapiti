#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2024 Cyberwatch
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
import json
from typing import Optional
from urllib.parse import urljoin

from bs4 import BeautifulSoup
from httpx import RequestError

from wapitiCore.attack.network_devices.network_device_common import NetworkDeviceCommon, MSG_TECHNO_VERSIONED
from wapitiCore.net import Request
from wapitiCore.net.response import Response
from wapitiCore.definitions.fingerprint import SoftwareNameDisclosureFinding
from wapitiCore.main.log import log_blue, logging

MSG_NO_UBIKA = "No UBIKA Detected"


class ModuleUbika(NetworkDeviceCommon):
    """Detect Ubika."""
    version = []

    async def check_ubika(self, url):
        check_list = ['app/monitor/']
        for item in check_list:
            full_url = urljoin(url, item)
            request = Request(full_url, 'GET')
            try:
                response: Response = await self.crawler.async_send(request, follow_redirects=True)
            except RequestError:
                self.network_errors += 1
                raise
            soup = BeautifulSoup(response.content, 'html.parser')
            title_tag = soup.title
            return response.is_success and title_tag and "UBIKA" in title_tag.text.strip()

    async def get_ubika_version(self, url):
        versions = []
        version_uri = "app/monitor/api/info/product"
        full_url = urljoin(url, version_uri)
        request = Request(full_url, 'GET')
        try:
            response: Response = await self.crawler.async_send(request, follow_redirects=True)
        except RequestError:
            self.network_errors += 1
            raise

        if response.is_success:
            version = response.json.get("result", {}).get("product", {}).get("version", '')
            if version:
                versions.append(version)
        return versions

    async def attack(self, request: Request, response: Optional[Response] = None):
        self.finished = True
        request_to_root = Request(request.url)

        try:
            if await self.check_ubika(request_to_root.url):
                try:
                    self.version = await self.get_ubika_version(request_to_root.url)
                except RequestError as req_error:
                    self.network_errors += 1
                    logging.error(f"Request Error occurred: {req_error}")

                ubika_detected = {
                    "name": "UBIKA WAAP",
                    "versions": self.version,
                    "categories": ["Network Equipment"],
                    "groups": ["Content"]
                }
                log_blue(
                    MSG_TECHNO_VERSIONED,
                    "UBIKA WAAP",
                    self.version
                )

                await self.add_info(
                    finding_class=SoftwareNameDisclosureFinding,
                    request=request_to_root,
                    info=json.dumps(ubika_detected),
                )
                self.version.clear()
            else:
                log_blue(MSG_NO_UBIKA)
        except RequestError as req_error:
            self.network_errors += 1
            logging.error(f"Request Error occurred: {req_error}")
