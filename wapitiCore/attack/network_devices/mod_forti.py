#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2025 Cyberwatch
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
from string import ascii_lowercase
import random

from bs4 import BeautifulSoup
from httpx import RequestError

from wapitiCore.attack.network_devices.network_device_common import NetworkDeviceCommon, MSG_TECHNO_VERSIONED
from wapitiCore.definitions.cve_2024_55591 import FortiAuthenticationBypass
from wapitiCore.net import Request
from wapitiCore.net.response import Response
from wapitiCore.definitions.fingerprint import SoftwareNameDisclosureFinding
from wapitiCore.main.log import log_blue, logging, log_verbose, log_red

MSG_NO_FORTI = "No Forti Product Detected"
MSG_CVE_2024_55591 = "[!] {0} is vulnerable to CVE-2024-55591 !"


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
            'login/?next=/',
            'login?redir='
        ]

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

        # Check for other Fortinet products
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
        if 'class="main-app"' in response.content:
            return True

        return False

    async def detect_cve_2024_55591(self, base_url):
        """
        Detects if the Fortinet FortiOS or FortiProxy is vulnerable to CVE-2024-55591.
        This function was adapted from the WatchTowrLabs POC project of detecting the CVE-2024-55591 vulnerability
        Source: https://github.com/watchtowrlabs/fortios-auth-bypass-check-CVE-2024-55591
        """

        #Send a request to a specific endpoint
        login_endpoint = "login?redir=/ng"
        login_url = urljoin(base_url, login_endpoint)
        login_request = Request(login_url, 'GET')
        try:
            # Send the WebSocket-like request
            login_response: Response = await self.crawler.async_send(login_request, follow_redirects=False)
        except RequestError:
            self.network_errors += 1
            raise

        # Generate a random endpoint suffix
        random_suffix = ''.join(random.choices(ascii_lowercase, k=8))
        test_uri = f"wapiti3-{random_suffix}"
        test_url = urljoin(base_url, test_uri)

        # WebSocket handshake headers
        test_headers = {
            "Sec-WebSocket-Version": "13",
            "Sec-WebSocket-Key": "thFz/fKwzu5wDEy0XO3fcw==",
            "Connection": "keep-alive, Upgrade",
            "Upgrade": "websocket"
        }
        request = Request(test_url, 'GET')
        try:
            # Send the WebSocket-like request
            test_response: Response = await self.crawler.async_send(request, follow_redirects=False, headers=test_headers)
        except RequestError:
            self.network_errors += 1
            raise

        # Analyze the response status code
        login_request_status_check = login_response.status == 200
        test_request_status_check = test_response.status == 101

        # Check body content validation

        main_app_check = '<html class="main-app">' in login_response.content
        f_icon_warning_check = '<f-icon class="fa-warning' in login_response.content
        f_icon_closing_check = '</f-icon>' in login_response.content

        body_checks = main_app_check and f_icon_warning_check and f_icon_closing_check

        # Check for APSCOOKIE header
        header_marker_check = any('APSCOOKIE_' in str(header) for header in login_response.headers.values())

        # Check connection upgrade for second response
        connection_upgrade_check = 'Upgrade' in test_response.headers.get('Connection', '')

        return all([
            login_request_status_check,
            test_request_status_check,
            body_checks,
            header_marker_check,
            connection_upgrade_check
        ])

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

                if await self.detect_cve_2024_55591(request.url):
                    log_red(
                        MSG_CVE_2024_55591,
                        request_to_root.url
                    )
                    await self.add_critical(
                        finding_class=FortiAuthenticationBypass,
                        request=request,
                        info=f"URL {request.url} seems vulnerable to CVE-2024-55591",
                        response=response
                    )
                else:
                    log_blue("Not vulnerable to CVE-2024-55591")

            else:
                log_blue(MSG_NO_FORTI)
        except RequestError as req_error:
            self.network_errors += 1
            logging.error(f"Request Error occurred: {req_error}")
