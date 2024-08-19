#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2021-2024 Cyberwatch
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
import xml
import xml.etree.ElementTree as ET
from os.path import join as path_join
from typing import Match, Optional
from httpx import RequestError

from wapitiCore.attack.attack import Attack, random_string
from wapitiCore.definitions.fingerprint import SoftwareNameDisclosureFinding
from wapitiCore.definitions.fingerprint_webapp import SoftwareVersionDisclosureFinding
from wapitiCore.main.log import log_blue, log_orange, logging
from wapitiCore.net.response import Response
from wapitiCore.net import Request

MSG_TECHNO_VERSIONED = "{0} {1} detected"
MSG_NO_WP = "No WordPress Detected"
MSG_WP_VERSION = "WordPress Version : {0}"


class ModuleWpEnum(Attack):
    """Detect WordPress Plugins with version."""
    name = "wp_enum"
    PAYLOADS_FILE_PLUGINS = "wordpress_plugins.txt"
    PAYLOADS_FILE_THEMES = "wordpress_themes.txt"
    false_positive = {"plugins": False, "themes": False}

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

    async def detect_version(self, url: str):
        rss_urls = ["feed/", "comments/feed/", "feed/rss/", "feed/rss2/"]
        detected_version = None

        for rss_url in rss_urls:
            request = Request(f"{url}{'' if url.endswith('/') else '/'}{rss_url}", "GET")
            response: Response = await self.crawler.async_send(request, follow_redirects=True)

            if not response.content or response.is_error or "content-type" not in response.headers:
                continue
            if "xml" not in response.headers["content-type"]:
                log_orange(f"Response content-type for {rss_url} is not XML")
                continue
            root = ET.fromstring(response.content)

            if root is None:
                continue

            try:
                generator_text = root.findtext('./channel/generator')
            except xml.etree.ElementTree.ParseError:
                continue

            if not generator_text:
                continue

            version: Match = re.search(r"\Ahttps?:\/\/wordpress\.(?:[a-z]+)\/\?v=(.*)\Z", generator_text)
            if version is None:
                continue

            detected_version = version.group(1)
            break

        log_blue(
            MSG_WP_VERSION,
            detected_version or "N/A"
        )
        info_content = {"name": "WordPress", "versions": [], "categories": ["CMS", "Blogs"], "groups": ["Content"]}

        if detected_version:
            info_content["versions"].append(detected_version)
            await self.add_info(
                finding_class=SoftwareVersionDisclosureFinding,
                request=request,
                info=json.dumps(info_content)
            )

        await self.add_info(
            finding_class=SoftwareNameDisclosureFinding,
            request=request,
            info=json.dumps(info_content)
        )

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

    @staticmethod
    def check_wordpress(response: Response):
        if re.findall('WordPress.*', response.content):
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

        response = await self.crawler.async_send(request_to_root, follow_redirects=True)
        if self.check_wordpress(response):
            await self.detect_version(request_to_root.url)
            await self.check_false_positive(request_to_root.url)
            log_blue("----")
            log_blue("Enumeration of WordPress Plugins :")
            await self.detect_plugin(request_to_root.url)
            log_blue("----")
            log_blue("Enumeration of WordPress Themes :")
            await self.detect_theme(request_to_root.url)
        else:
            log_blue(MSG_NO_WP)
