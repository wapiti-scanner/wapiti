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
from wapitiCore.main.log import log_blue, logging

MSG_NO_DRUPAL = "No Drupal Detected"


class ModuleDrupalEnum(CommonCMS):
    """Detect Drupal version."""
    PAYLOADS_HASH = "drupal_hash_files.json"

    versions = []

    async def check_drupal(self, url):
        check_list = ['core/misc/drupal.js', 'misc/drupal.js']
        for item in check_list:
            request = Request(f'{url}{item}', 'GET')
            try:
                response: Response = await self.crawler.async_send(request, follow_redirects=True)
            except RequestError:
                self.network_errors += 1
            except Exception as exception:
                logging.exception(exception)
            else:
                if (
                    response.is_success
                    and "content-type" in response.headers
                    and "javascript" in response.headers["content-type"]
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

        if await self.check_drupal(request_to_root.url):
            await self.detect_version(self.PAYLOADS_HASH, request_to_root.url)  # Call the method on the instance
            self.versions = sorted(self.versions, key=lambda x: x.split('.')) if self.versions else []

            drupal_detected = {
                "name": "Drupal",
                "versions": self.versions,
                "categories": ["CMS Drupal"],
                "groups": ["Content"]
            }

            log_blue(
                MSG_TECHNO_VERSIONED,
                "Drupal",
                self.versions
            )

            if self.versions:
                await self.add_info(
                    finding_class=SoftwareVersionDisclosureFinding,
                    request=request_to_root,
                    info=json.dumps(drupal_detected),
                )
            await self.add_info(
                finding_class=SoftwareNameDisclosureFinding,
                request=request_to_root,
                info=json.dumps(drupal_detected),
            )
        else:
            log_blue(MSG_NO_DRUPAL)
