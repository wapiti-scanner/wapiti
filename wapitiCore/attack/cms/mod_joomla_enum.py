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
from httpx import RequestError

from wapitiCore.net import Request
from wapitiCore.attack.cms.cms_common import CommonCMS, MSG_TECHNO_VERSIONED
from wapitiCore.net.response import Response
from wapitiCore.definitions.fingerprint_webapp import SoftwareVersionDisclosureFinding
from wapitiCore.definitions.fingerprint import SoftwareNameDisclosureFinding
from wapitiCore.main.log import log_blue

MSG_NO_JOOMLA = "No Joomla Detected"


class ModuleJoomlaEnum(CommonCMS):
    """Detect Joomla version."""
    PAYLOADS_HASH = "joomla_hash_files.json"

    versions = []

    async def check_joomla(self, url):

        request = Request(f'{url}', 'GET')
        try:
            response: Response = await self.crawler.async_send(request, follow_redirects=True)
        except RequestError:
            self.network_errors += 1
        else:
            if (
                response.is_success and
                ("/administrator/" in response.content or
                 "Joomla" in response.headers.get('X-Powered-By', '') or
                 "media/jui/css" in response.content or
                 "media/system/js" in response.content)
               ):
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

        if await self.check_joomla(request_to_root.url):
            await self.detect_version(self.PAYLOADS_HASH, request_to_root.url)
            self.versions = sorted(self.versions, key=lambda x: x.split('.')) if self.versions else []

            joomla_detected = {
                "name": "Joomla!",
                "versions": self.versions,
                "categories": ["CMS Joomla"],
                "groups": ["Content"]
            }

            log_blue(
                MSG_TECHNO_VERSIONED,
                "Joomla!",
                self.versions
            )

            if self.versions:
                await self.add_info(
                    finding_class=SoftwareVersionDisclosureFinding,
                    request=request_to_root,
                    info=json.dumps(joomla_detected),
                )
            await self.add_info(
                finding_class=SoftwareNameDisclosureFinding,
                request=request_to_root,
                info=json.dumps(joomla_detected),
            )
        else:
            log_blue(MSG_NO_JOOMLA)
