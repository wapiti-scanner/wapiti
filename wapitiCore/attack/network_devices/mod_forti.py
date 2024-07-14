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
from wapitiCore.main.log import log_blue, logging, log_verbose

MSG_NO_FORTI = "No Forti Product Detected"


class ModuleForti(NetworkDeviceCommon):
    """Detect Forti."""
    device_name = "Fortinet"
    version = []
    fortinet_pattern = re.compile(r'Forti\w+')

    async def check_forti(self, url):
        fortivpn_list = ['remote/fgt_lang?lang=en',
                         'remote/fgt_lang?lang=fr']
        fortiweb_list = ['fgt_lang.js?paths=lang/en:com_info',
                         'fgt_lang.js?paths=lang/fr:com_info']
        check_list = fortivpn_list + fortiweb_list + [
            'logindisclaimer',
            'remote/login?lang=en',
            'remote/login?lang=fr',
            'fpc/app/login',
            'login/?next=/'
        ]

        for item in check_list:
            full_url = urljoin(url, item)
            request = Request(full_url, 'GET')
            try:
                response: Response = await self.crawler.async_send(request, follow_redirects=False)
                log_verbose(f"[¨] {request}")
            except RequestError:
                self.network_errors += 1
                continue

            if response.is_success:
                if "content-type" in response.headers and \
                        "javascript" in response.headers["content-type"]:
                    if item in fortivpn_list:
                        self.device_name = "Fortinet SSL-VPN"
                        return True
                    if item in fortiweb_list:
                        self.device_name = "FortiWeb"
                        return True
                return await self.detect_forti_product(full_url)

        # Check Fortinet product from title
        request = Request(url, 'GET')
        try:
            response: Response = await self.crawler.async_send(request, follow_redirects=False)
            log_verbose(f"[¨] {request}")
        except RequestError:
            self.network_errors += 1
            raise
        if response.is_success:
            soup = BeautifulSoup(response.content, 'html.parser')
            # Get the title of the webpage
            title_tag = soup.title
            if title_tag:
                title = title_tag.string
                # Check if the title contains a name starting with "Forti" (case-sensitive)
                if title and "Forti" in title:
                    self.device_name = title
                    return True

        # Check FortiMail
        url_fortimail = urljoin(url, "admin/")
        request = Request(url_fortimail, 'GET')
        try:
            response: Response = await self.crawler.async_send(request, follow_redirects=False)
            log_verbose(f"[¨] {request}")
        except RequestError:
            self.network_errors += 1
            raise
        if response.is_success:
            soup = BeautifulSoup(response.content, 'html.parser')
            for tag in soup.find_all(True):
                if tag.string:
                    match = self.fortinet_pattern.search(tag.text)
                    if match:
                        # Extract the matched product name
                        self.device_name = match.group()
                        return True

        # Check FortiManager and FortiAnalyzer
        url_fortimanager = urljoin(url, "p/login/")
        request = Request(url_fortimanager, 'GET')
        try:
            response: Response = await self.crawler.async_send(request, follow_redirects=False)
            log_verbose(f"[¨] {request}")
        except RequestError:
            self.network_errors += 1
            raise
        if response.is_success:
            soup = BeautifulSoup(response.content, 'html.parser')
            title_tag = soup.title
            sign_in_header_div = soup.find('div', class_='sign-in-header')

            for device_name in ["FortiManager", "FortiAnalyzer"]:
                if title_tag:
                    if device_name in title_tag.string:
                        self.device_name = device_name
                        return True
                # if custom title without Forti*, we check for specific div
                if sign_in_header_div and device_name in sign_in_header_div.text:
                    self.device_name = device_name
                    return True
        return False

    async def detect_forti_product(self, url):
        request = Request(url, 'GET')
        try:
            # Send an HTTP GET request to the URL
            response: Response = await self.crawler.async_send(request, follow_redirects=True)
            log_verbose(f"[¨] {request}")
        except RequestError:
            self.network_errors += 1
            raise
        soup = BeautifulSoup(response.content, 'html.parser')

        # Get the title of the webpage
        title_tag = soup.title
        if title_tag:
            title = title_tag.string

            # Search for the pattern in the title
            match = self.fortinet_pattern.search(title)

            if match:
                # Extract the matched product name
                self.device_name = match.group()
                return True
        return False

    async def attack(self, request: Request, response: Optional[Response] = None):
        self.finished = True
        request_to_root = Request(request.url)

        try:
            if await self.check_forti(request_to_root.url):

                forti_detected = {
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
                    info=json.dumps(forti_detected),
                )
            else:
                log_blue(MSG_NO_FORTI)
        except RequestError as req_error:
            self.network_errors += 1
            logging.error(f"Request Error occurred: {req_error}")
