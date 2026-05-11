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

from wapitiCore.parsers.html_parser import Html
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
MSG_NO_IVANTI = "No Ivanti Product Detected"

class ModuleIvanti(NetworkDeviceCommon):
    """Detect Ivanti."""
    version = []
    device_name = ""

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
            page = Html(response.content, full_url)
            frmLogin = page.soup.find(name="frmLogin")
            if response.is_success and ("Ivanti Connect Secure" in page.title or frmLogin is not None):
                return True
        return False


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
            page = Html(response.content, full_url)
            if response.is_success and "Ivanti Service Manager" in page.title:
                return True
            h1_tag = page.soup.h1
            if h1_tag and response.is_success and "Ivanti Service Manager" in h1_tag.text.strip():
                return True
            if '/lib/RespondJs/respond.min.js' in response.content:
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
            page = Html(response.content, full_url)
            if response.is_success and page.title in ["Ivanti User Portal",
                    "Ivanti Portail utilisateur",
                    "Ivanti Admin Portal"]:
                return True
            h1_tag = page.soup.h1
            if h1_tag and response.is_success and "MI_LOGIN_SCREEN" in h1_tag.text.strip():
                return True
        return False

    async def attack(self, request: Request, response: Optional[Response] = None):
        self.finished = True
        request_to_root = Request(request.url)

        try:
            if await self.check_ivanti_connect_secure(request_to_root.url):
                self.device_name = "Ivanti Connect Secure"
                log_blue(MSG_IVANTI_CONNECT)
            elif await self.check_ivanti_service_manager(request_to_root.url):
                self.device_name = "Ivanti Service Manager"
                log_blue(MSG_IVANTI_SERVICE_MANAGER)
            elif await self.check_ivanti_user_portal(request_to_root.url):
                self.device_name = "Ivanti User Portal"
                log_blue(MSG_IVANTI_USER_PORTAL)
            else:
                log_blue(MSG_NO_IVANTI)

            if self.device_name:
                ivanti_detected = {
                    "name": self.device_name,
                    "versions": self.version,
                    "categories": ["Network Equipment"],
                    "groups": ["Content"]
                }
                await self.add_info(
                    finding_class=SoftwareNameDisclosureFinding,
                    request=request_to_root,
                    info=json.dumps(ivanti_detected),
                )

        except RequestError as req_error:
            self.network_errors += 1
            logging.error(f"Request Error occurred: {req_error}")
