#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2023-2024 Cyberwatch
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
from bs4 import BeautifulSoup
from httpx import RequestError

from wapitiCore.net import Request
from wapitiCore.attack.cms.cms_common import CommonCMS, MSG_TECHNO_VERSIONED
from wapitiCore.net.response import Response
from wapitiCore.definitions.fingerprint_webapp import SoftwareVersionDisclosureFinding
from wapitiCore.definitions.fingerprint import SoftwareNameDisclosureFinding
from wapitiCore.main.log import log_blue

MSG_NO_PRESTASHOP = "No PrestaShop Detected"


class ModulePrestashopEnum(CommonCMS):
    """Detect PrestaShop version."""
    PAYLOADS_HASH = "prestashop_hash_files.json"

    versions = []

    async def check_prestashop(self, url):

        request = Request(f'{url}', 'GET')
        try:
            response: Response = await self.crawler.async_send(request, follow_redirects=True)
        except RequestError:
            self.network_errors += 1
        else:
            soup = BeautifulSoup(response.content, 'html.parser')

            # Look for common PrestaShop elements or text
            common_prestashop_elements = [
                "PrestaShop",  # Look for the presence of the text "PrestaShop"
                "prestashop.min.css",  # Check for the CSS file often used by PrestaShop
                "PrestaShop.modules",  # Check for JavaScript code often used by PrestaShop
                "Powered by <a href='https://www.prestashop.com'",  # Detects "Powered by PrestaShop" text
                "prestashop-bootstrap.min.css",  # Check for another common CSS file
                "prestashop.js",
                "/revsliderprestashop/",
                "prestashop-widget",
                "for_prestashop",
                "themes/.*/assets",
                "prestashop ="
                # Check for another common JavaScript file
            ]
            # Check for the presence of any common PrestaShop elements or text
            for element in common_prestashop_elements:
                if element in str(soup):
                    return True

        return False

    async def must_attack(self, request: Request, response: Optional[Response] = None):
        if self.finished:
            return False

        if request.method == "POST":
            return False

        return request.url == await self.persister.get_root_url()

    async def attack(self, request: Request, response: Optional[Response] = None):
        self.finished = True
        request_to_root = Request(request.url)

        if await self.check_prestashop(request_to_root.url):
            await self.detect_version(self.PAYLOADS_HASH, request_to_root.url)
            self.versions = sorted(self.versions, key=lambda x: x.split('.')) if self.versions else []

            prestashop_detected = {
                "name": "PrestaShop",
                "versions": self.versions,
                "categories": ["CMS PrestaShop"],
                "groups": ["Content"]
            }

            log_blue(
                MSG_TECHNO_VERSIONED,
                "PrestaShop",
                self.versions
            )

            if self.versions:
                await self.add_info(
                    finding_class=SoftwareVersionDisclosureFinding,
                    request=request_to_root,
                    info=json.dumps(prestashop_detected),
                )
            await self.add_info(
                finding_class=SoftwareNameDisclosureFinding,
                request=request_to_root,
                info=json.dumps(prestashop_detected),
            )
        else:
            log_blue(MSG_NO_PRESTASHOP)
