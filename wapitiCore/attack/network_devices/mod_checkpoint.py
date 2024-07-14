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
import re
from typing import Optional
from urllib.parse import urljoin

from bs4 import BeautifulSoup
from httpx import RequestError

from wapitiCore.attack.network_devices.network_device_common import NetworkDeviceCommon, MSG_TECHNO_VERSIONED
from wapitiCore.net import Request
from wapitiCore.net.response import Response
from wapitiCore.definitions.fingerprint import SoftwareNameDisclosureFinding
from wapitiCore.main.log import log_blue, logging

MSG_NO_CHECKPOINT = "No Check Point Product Detected"
MSG_CHECKPOINT_DETECTED = "{0} {1} Detected !"


class ModuleCheckPoint(NetworkDeviceCommon):
    """Detect Check Point Devices."""

    device_name = "Check Point"
    version = []

    async def check_checkpoint(self, url):
        check_list = ['cgi-bin/home.tcl', 'sslvpn/Login/Login',
                      'sslvpn/ICS/scanPage', 'portail/Login/Login', 'Login/Login']

        for item in check_list:
            full_url = urljoin(url, item)
            request = Request(full_url, 'GET')
            try:
                response: Response = await self.crawler.async_send(request, follow_redirects=False)
            except RequestError:
                self.network_errors += 1
                continue

            if response.is_success:
                soup = BeautifulSoup(response.content, 'html.parser')
                scripts = soup.find_all('script')
                for script in scripts:
                    if script.has_attr('src') and script['src'].endswith('/login/login.js'):
                        self.version = await self.detect_checkpoint_version(response.content)
                        return True
                    if script.string and "realmsArrJSON =" in script.string:
                        return True
                if 'Check Point Software Technologies Ltd' in response.content:
                    return True

        return False

    async def detect_checkpoint_version(self, response_content):
        version = []
        soup = BeautifulSoup(response_content, 'html.parser')
        scripts = [script for script in soup.find_all('script') if not script.has_attr('src')]
        for script in scripts:
            if script.string:
                # Define the pattern to match the version variable
                pattern = r"var version='([^']*)'"
                match = re.search(pattern, script.string)
                if match:
                    version.append(match.group(1))
        return version

    async def attack(self, request: Request, response: Optional[Response] = None):
        self.finished = True
        request_to_root = Request(request.url)

        try:
            if await self.check_checkpoint(request_to_root.url):
                checkpoint_detected = {
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
                    info=json.dumps(checkpoint_detected),
                )
            else:
                log_blue(MSG_NO_CHECKPOINT)
        except RequestError as req_error:
            self.network_errors += 1
            logging.error(f"Request Error occurred: {req_error}")
