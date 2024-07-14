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

from httpx import RequestError

from wapitiCore.attack.network_devices.network_device_common import NetworkDeviceCommon, MSG_TECHNO_VERSIONED
from wapitiCore.net import Request
from wapitiCore.net.response import Response
from wapitiCore.definitions.fingerprint import SoftwareNameDisclosureFinding
from wapitiCore.main.log import log_blue, logging

MSG_NO_HARBOR = "No Harbor Product Detected"


class ModuleHarbor(NetworkDeviceCommon):
    """Detect Harbor."""

    device_name = "Harbor"
    version = []

    async def check_harbor(self, url):
        check_list = ['api/v2.0/systeminfo']

        for item in check_list:
            full_url = urljoin(url, item)
            request = Request(full_url, 'GET')
            try:
                response: Response = await self.crawler.async_send(request, follow_redirects=False)
            except RequestError:
                self.network_errors += 1
                raise

            if (response.is_success and "content-type" in response.headers
                    and "json" in response.headers["content-type"]):
                try:
                    await self.detect_harbor_version(response.content)
                except ValueError:
                    logging.error(f"Cannot extract version from {full_url}")
                return True

        return False

    async def detect_harbor_version(self, response_content):
        try:
            # Parse the JSON content
            data = json.loads(response_content)
            # Extract the harbor_version value
            if data.get("harbor_version"):
                self.version.append(data.get("harbor_version"))
        except (json.JSONDecodeError, KeyError) as json_error:
            raise ValueError("The URL doesn't contain a valid JSON.") from json_error

    async def attack(self, request: Request, response: Optional[Response] = None):
        self.finished = True
        request_to_root = Request(request.url)

        try:
            if await self.check_harbor(request_to_root.url):
                harbor_detected = {
                    "name": self.device_name,
                    "versions": self.version,
                    "categories": ["Network Equipment"],
                    "groups": ["Content"]
                }
                log_blue(
                    MSG_TECHNO_VERSIONED,
                    self.device_name,
                    self.version
                )

                await self.add_info(
                    finding_class=SoftwareNameDisclosureFinding,
                    request=request_to_root,
                    info=json.dumps(harbor_detected),
                )
                self.version.clear()
            else:
                log_blue(MSG_NO_HARBOR)
        except RequestError as req_error:
            self.network_errors += 1
            logging.error(f"Request Error occurred: {req_error}")

