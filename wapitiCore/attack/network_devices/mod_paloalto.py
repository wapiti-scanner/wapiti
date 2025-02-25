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
from datetime import datetime, timezone, timedelta
from bs4 import BeautifulSoup
from httpx import RequestError

from wapitiCore.attack.attack import Attack
from wapitiCore.net import Request
from wapitiCore.net.response import Response
from wapitiCore.definitions.fingerprint import SoftwareNameDisclosureFinding
from wapitiCore.main.log import log_blue, logging

MSG_NO_PALO_ALTO = "No Palo Alto Product Detected"
MSG_PALO_ALTO_GLOBALPROTECT_DETECTED = "Palo Alto GlobalProtect Portal Detected !"

class ModulePaloAlto(Attack):
    """Detect Palo Alto Devices."""
    version = []
    device_name = "Palo Alto"


#La détection de version panOS est grandement inspiré de cette application https://github.com/noperator/panos-scanner
    def check_date(self,version_table: dict, dateEtag: datetime.date) -> list:
        versions = [
            version for version, date in version_table.items() if date == dateEtag
        ]
        return versions


    def load_version_table(self) -> dict:
        with open("wapitiCore/data/attacks/version-table-Etag-palo-alto.txt", "r") as versionTableFile:
            entries = [line.strip().split() for line in versionTableFile.readlines()]
        return {
            e[0]: datetime.strptime(" ".join(e[1:]), "%b %d %Y").date()
            for e in entries
        }


    async def check_palo_alto_global_protect_portal(self, url):
        check_list = ['global-protect/login.esp', '']
        for item in check_list:
            full_url = urljoin(url, item)
            request = Request(full_url, 'GET')
            try:
                response: Response = await self.crawler.async_send(request, follow_redirects=False)
            except RequestError:
                self.network_errors += 1
                continue
            soup = BeautifulSoup(response.content, 'html.parser')
            title_tag = soup.title
            div_header = soup.find(id="heading")
            if response.is_success:
                if title_tag and "GlobalProtect Portal" in title_tag.text.strip():
                    return True
                elif div_header and "GlobalProtect Portal" in div_header.text.strip():
                    return True
                elif soup.pan_form is not None:
                    return True

        return False

    async def detect_panos_version(self, url):
        check_list = ['global-protect/portal/css/bootstrap.min.css',
            'global-protect/portal/css/latofonts.css',
            'global-protect/portal/js/jquery.min.js',
            'global-protect/portal/css/login.css',
            'global-protect/portal/images/favicon.ico',
            'js/Pan.js',
            'global-protect/portal/images/bg.png'
        ]
        for item in check_list:
            full_url = urljoin(url, item)
            request = Request(full_url, 'GET')
            try:
                response: Response = await self.crawler.async_send(request, follow_redirects=False)
            except RequestError:
                self.network_errors += 1
                continue
            version_table= self.load_version_table()
            fullEtag=response.headers.get("Etag")
            if(fullEtag and len(fullEtag)>=8):
                if '-' in fullEtag:
                    shortenEtag = fullEtag.split('-', 1)[0]
                else:
                    shortenEtag = fullEtag[-8:]
                date = datetime.fromtimestamp(int(shortenEtag,16),timezone.utc).date()
                self.version = self.check_date(version_table,date)
                return True
        return False


    async def attack(self, request: Request, response: Optional[Response] = None):
        self.finished = True
        request_to_root = Request(request.url)
        try:
            if await self.check_palo_alto_global_protect_portal(request_to_root.url):
                palo_alto_detected = {
                    "name": "Palo Alto GlobalProtect Portal",
                    "categories": ["Network Equipment"],
                    "groups": ["Content"]
                }
                log_blue(
                    MSG_PALO_ALTO_GLOBALPROTECT_DETECTED
                )

                await self.add_info(
                    finding_class=SoftwareNameDisclosureFinding,
                    request=request_to_root,
                    info=json.dumps(palo_alto_detected),
                )
            if await self.detect_panos_version(request_to_root.url):
                palo_alto_detected = {
                    "name": "Palo Alto GlobalProtect Portal",
                    "versions": self.version,
                    "categories": ["Network Equipment"],
                    "groups": ["Content"]
                }
                log_blue(
                    MSG_PALO_ALTO_GLOBALPROTECT_DETECTED
                )

                await self.add_info(
                    finding_class=SoftwareNameDisclosureFinding,
                    request=request_to_root,
                    info=json.dumps(palo_alto_detected),
                )
            else:
                log_blue(MSG_NO_PALO_ALTO)
        except RequestError as req_error:
            self.network_errors += 1
            logging.error(f"Request Error occurred: {req_error}")
