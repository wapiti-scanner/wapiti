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
import re
from os.path import join as path_join
from typing import Optional
from httpx import RequestError

from wapitiCore.net import Request
from wapitiCore.attack.cms.cms_common import CommonCMS, MSG_TECHNO_VERSIONED
from wapitiCore.attack.attack import random_string
from wapitiCore.net.response import Response
from wapitiCore.definitions.fingerprint_webapp import SoftwareVersionDisclosureFinding
from wapitiCore.definitions.fingerprint import SoftwareNameDisclosureFinding
from wapitiCore.main.log import log_blue, logging

MSG_NO_WP = "No WordPress Detected"


class ModuleWpEnum(CommonCMS):
    """Detect Drupal version."""
    PAYLOADS_HASH = "wp_hash_files.json"
    PAYLOADS_FILE_PLUGINS = "wordpress_plugins.txt"
    PAYLOADS_FILE_THEMES = "wordpress_themes.txt"
    versions = []
    false_positive = {"plugins": False, "themes": False}

    async def check_wp(self, url):
        check_list = [
            "wp-content",
            "wp-json",
            "wp-includes",
            "wp-admin",
            "generator\" content=\"wordpress",  # Check for the generator meta tag
            "wp-embed-responsive",  # Check for WordPress oEmbed script
        ]
        request = Request(f'{url}', 'GET')
        try:
            response: Response = await self.crawler.async_send(request, follow_redirects=True)
        except RequestError:
            self.network_errors += 1
        except Exception as exception:
            logging.exception(exception)
        else:
            if any(indicator in response.content for indicator in check_list):
                return True  # WordPress indicator found

        return False

    async def check_false_positive(self, url):
        self.false_positive = {"plugins": False, "themes": False}
        rand = random_string()
        for wp_type in ["plugins", "themes"]:
            request = Request(f'{url}/wp-content/{wp_type}/{rand}/readme.txt', 'GET')
            try:
                response: Response = await self.crawler.async_send(request)
            except RequestError:
                self.network_errors += 1
            else:
                if response.status == 403 or response.is_success:
                    logging.warning(f"False positive detected for {wp_type} due to status code {response.status}")
                    self.false_positive[wp_type] = response.status

    def get_plugin(self):
        with open(
            path_join(self.DATA_DIR, self.PAYLOADS_FILE_PLUGINS),
            errors="ignore",
            encoding='utf-8'
        ) as plugin_list:
            for line in plugin_list:
                plugin = line.strip()
                if plugin:
                    yield plugin

    def get_theme(self):
        with open(
            path_join(self.DATA_DIR, self.PAYLOADS_FILE_THEMES),
            errors="ignore",
            encoding='utf-8'
        ) as theme_list:
            for line in theme_list:
                theme = line.strip()
                if theme:
                    yield theme

    async def detect_plugin(self, url):
        for plugin in self.get_plugin():
            if self._stop_event.is_set():
                break

            request = Request(f'{url}/wp-content/plugins/{plugin}/readme.txt', 'GET')
            try:
                response: Response = await self.crawler.async_send(request)
            except RequestError:
                self.network_errors += 1
            else:
                if response.is_success:
                    version = re.search(r'tag:\s*([\d.]+)', response.content)

                    # This check was added to detect invalid format of "Readme.txt" which can cause a crash
                    if version:
                        version = version.group(1)
                    else:
                        version = ""

                    if version or \
                        self.false_positive["plugins"] < 200 or self.false_positive["plugins"] > 299:
                        plugin_detected = {
                            "name": plugin,
                            "versions": [version],
                            "categories": ["WordPress plugins"],
                            "groups": ['Add-ons']
                        }
                        log_blue(
                            MSG_TECHNO_VERSIONED,
                            plugin,
                            [version]
                        )
                        await self.add_info(
                            finding_class=SoftwareNameDisclosureFinding,
                            request=request,
                            info=json.dumps(plugin_detected),
                            response=response
                        )
                elif response.status == 403 and self.false_positive["plugins"] != 403:
                    plugin_detected = {
                        "name": plugin,
                        "versions": [""],
                        "categories": ["WordPress plugins"],
                        "groups": ['Add-ons']
                    }
                    log_blue(
                        MSG_TECHNO_VERSIONED,
                        plugin,
                        [""]
                    )
                    await self.add_info(
                        finding_class=SoftwareNameDisclosureFinding,
                        request=request,
                        info=json.dumps(plugin_detected),
                        response=response
                    )

    async def detect_theme(self, url):
        for theme in self.get_theme():
            if self._stop_event.is_set():
                break

            request = Request(f'{url}/wp-content/themes/{theme}/readme.txt', 'GET')
            try:
                response: Response = await self.crawler.async_send(request)
            except RequestError:
                self.network_errors += 1
            else:
                if response.is_success:
                    version = re.search(r'tag:\s*([\d.]+)', response.content)
                    # This check was added to detect invalid format of "Readme.txt" which can cause a crash
                    if version:
                        version = version.group(1)
                    else:
                        version = ""

                    theme_detected = {
                        "name": theme,
                        "versions": [version],
                        "categories": ["WordPress themes"],
                        "groups": ['Add-ons']
                    }

                    if version or \
                        self.false_positive["themes"] < 200 or self.false_positive["themes"] > 299:
                        log_blue(
                            MSG_TECHNO_VERSIONED,
                            theme,
                            [version]
                        )
                        await self.add_info(
                            finding_class=SoftwareNameDisclosureFinding,
                            request=request,
                            info=json.dumps(theme_detected),
                            response=response
                        )
                elif response.status == 403 and self.false_positive["themes"] != 403:
                    theme_detected = {
                        "name": theme,
                        "versions": [""],
                        "categories": ["WordPress themes"],
                        "groups": ['Add-ons']
                    }
                    log_blue(
                        MSG_TECHNO_VERSIONED,
                        theme,
                        [""]
                    )
                    await self.add_info(
                        finding_class=SoftwareNameDisclosureFinding,
                        request=request,
                        info=json.dumps(theme_detected),
                        response=response
                    )

    async def must_attack(self, request: Request, response: Optional[Response] = None):
        if self.finished or request.method == "POST":
            return False

        return request.url == await self.persister.get_root_url()

    async def attack(self, request: Request, response: Optional[Response] = None):
        self.finished = True
        request_to_root = Request(request.url)

        if await self.check_wp(request_to_root.url):
            await self.detect_version(self.PAYLOADS_HASH, request_to_root.url)  # Call the method on the instance
            self.versions = sorted(self.versions, key=lambda x: x.split('.')) if self.versions else []

            wp_detected = {
                "name": "WordPress",
                "versions": self.versions,
                "categories": ["CMS WordPress"],
                "groups": ["Content"]
            }

            log_blue(
                MSG_TECHNO_VERSIONED,
                "WordPress",
                self.versions
            )

            if self.versions:
                await self.add_info(
                    finding_class=SoftwareVersionDisclosureFinding,
                    request=request_to_root,
                    info=json.dumps(wp_detected),
                )
            await self.add_info(
                finding_class=SoftwareNameDisclosureFinding,
                request=request_to_root,
                info=json.dumps(wp_detected),
            )
            await self.check_false_positive(request_to_root.url)
            log_blue("Enumeration of WordPress Plugins :")
            await self.detect_plugin(request_to_root.url)
            log_blue("----")
            log_blue("Enumeration of WordPress Themes :")
            await self.detect_theme(request_to_root.url)
        else:
            log_blue(MSG_NO_WP)
