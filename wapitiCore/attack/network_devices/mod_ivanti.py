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

from wapitiCore.attack.network_devices.network_device_common import NetworkDeviceCommon
from wapitiCore.net import Request
from wapitiCore.net.response import Response
from wapitiCore.definitions.fingerprint import SoftwareNameDisclosureFinding
from wapitiCore.main.log import log_blue, logging

MSG_NO_IVANTI_CONNECT = "No Ivanti Connect Secure Detected"
MSG_IVANTI_CONNECT = "Ivanti Connect Secure Detected"
MSG_IVANTI_SERVICE_MANAGER = "Ivanti Service Manager Detected"
MSG_NO_IVANTI_SERVICE_MANAGER = "No Ivanti Service Manager Detected"
MSG_IVANTI_USER_PORTAL = "Ivanti User Portal Detected"
MSG_NO_IVANTI_USER_PORTAL = "No Ivanti User Portal"

class ModuleIvanti(NetworkDeviceCommon):
    """Detect Ivanti."""
    version = []

    async def check_ivanti_connect_secure(self, url):
        check_list = ['dana-na/auth/url_default/welcome.cgi','']
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
            frmLogin = soup.find(name="frmLogin")
            return response.is_success and (title_tag and "Ivanti Connect Secure" in title_tag.text.strip()) \
                or frmLogin is not None


    async def check_ivanti_service_manager(self, url):
        check_list = ['dana/home/index.cgi',
            'dana-na/auth/url_default/welcome.cgi',
            'dana-na/auth/welcome.cgi',
            '/HEAT/Account/Login',
            'HEAT',
            'HEAT/lib/RespondJs/respond.min.js',
            'lib/RespondJs/respond.min.js',''
        ]
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
            h1_tag = soup.h1
            if title_tag:
                if response.is_success and "Ivanti Service Manager" in title_tag.text.strip():
                    return True
            if h1_tag:
                if response.is_success and "Ivanti Service Manager" in h1_tag.text.strip():
                    return True
            if '/lib/RespondJs/respond.min.js' in str(soup):
                return True
            return False

    async def check_ivanti_user_portal(self, url):
        check_list = ['mifs/user/login.jsp','']
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
            h1_tag = soup.h1
            if title_tag:
                if response.is_success and title_tag.text.strip() in ["Ivanti User Portal",
                    "Ivanti Portail utilisateur",
                    "Ivanti Admin Portal"]:
                    return True
            if h1_tag:
                if response.is_success and "MI_LOGIN_SCREEN" in h1_tag.text.strip():
                    return True
            else:
                return False

    async def attack(self, request: Request, response: Optional[Response] = None):
        self.finished = True
        request_to_root = Request(request.url)

        try:
            if await self.check_ivanti_connect_secure(request_to_root.url):
                ivanti_detected = {
                    "name": "Ivanti Connect Secure",
                    "categories": ["Network Equipment"],
                    "groups": ["Content"]
                }
                log_blue(
                    MSG_IVANTI_CONNECT,
                )
                await self.add_info(
                    finding_class=SoftwareNameDisclosureFinding,
                    request=request_to_root,
                    info=json.dumps(ivanti_detected),
                )
            else:
                log_blue(MSG_NO_IVANTI_CONNECT)
            if await self.check_ivanti_service_manager(request_to_root.url):
                ivanti_detected = {
                    "name": "Ivanti Service Manager",
                    "categories": ["Network Equipment"],
                    "groups": ["Content"]
                }
                log_blue(
                    MSG_IVANTI_SERVICE_MANAGER,
                )
                await self.add_info(
                    finding_class=SoftwareNameDisclosureFinding,
                    request=request_to_root,
                    info=json.dumps(ivanti_detected),
                )
            else:
                log_blue(MSG_NO_IVANTI_SERVICE_MANAGER)
            if await self.check_ivanti_user_portal(request_to_root.url):
                ivanti_detected = {
                    "name": "Ivanti User Portal",
                    "categories": ["Network Equipment"],
                    "groups": ["Content"]
                }
                log_blue(
                    MSG_IVANTI_USER_PORTAL,
                )
                await self.add_info(
                    finding_class=SoftwareNameDisclosureFinding,
                    request=request_to_root,
                    info=json.dumps(ivanti_detected),
                )
            else:
                log_blue(MSG_NO_IVANTI_USER_PORTAL)
        except RequestError as req_error:
            self.network_errors += 1
            logging.error(f"Request Error occurred: {req_error}")
