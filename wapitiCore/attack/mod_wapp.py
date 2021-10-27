#!/usr/bin/env python3
# This file is part of the Wapiti project (https://wapiti.sourceforge.io)
# Copyright (C) 2020-2021 Nicolas Surribas
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
import os
import asyncio
import string
from httpx import RequestError

from wapitiCore.main.log import logging, log_blue
from wapitiCore.attack.attack import Attack
from wapitiCore.net.page import Page
from wapitiCore.wappalyzer.wappalyzer import Wappalyzer, ApplicationData, ApplicationDataException
from wapitiCore.language.vulnerability import _
from wapitiCore.definitions.fingerprint import NAME as TECHNO_DETECTED
from wapitiCore.definitions.fingerprint_webserver import NAME as WEB_SERVER_VERSIONED
from wapitiCore.definitions.fingerprint_webapp import NAME as WEB_APP_VERSIONED
from wapitiCore.net.web import Request

MSG_TECHNO_VERSIONED = _("{0} {1} detected")
MSG_CATEGORIES = _("  -> Categorie(s): {0}")
MSG_GROUPS = _("  -> Group(s): {0}")


class ModuleWapp(Attack):
    """
    Identify web technologies used by the web server using Wappalyzer database.
    """

    name = "wapp"

    WAPP_CATEGORIES_URL = "https://raw.githubusercontent.com/wapiti-scanner/wappalyzer/main/src/categories.json"
    WAPP_CATEGORIES = "categories.json"

    WAPP_GROUPS_URL = "https://raw.githubusercontent.com/wapiti-scanner/wappalyzer/main/src/groups.json"
    WAPP_GROUPS = "groups.json"

    WAPP_TECHNOLOGIES_BASE_URL = "https://raw.githubusercontent.com/wapiti-scanner/wappalyzer/main/src/technologies/"
    WAPP_TECHNOLOGIES = "technologies.json"

    do_get = False
    do_post = False
    user_config_dir = None
    finished = False

    def __init__(self, crawler, persister, attack_options, stop_event):
        Attack.__init__(self, crawler, persister, attack_options, stop_event)
        self.user_config_dir = self.persister.CONFIG_DIR

        if not os.path.isdir(self.user_config_dir):
            os.makedirs(self.user_config_dir)

    async def update(self):
        """Update the Wappalizer database from the web and load the patterns."""
        try:
            await self._load_wapp_database(
                self.WAPP_CATEGORIES_URL,
                self.WAPP_TECHNOLOGIES_BASE_URL,
                self.WAPP_GROUPS_URL
            )
        except IOError:
            logging.error(_("Error downloading wapp database."))

    async def must_attack(self, request: Request):
        if self.finished:
            return False

        if request.method == "POST":
            return False

        return request.url == await self.persister.get_root_url()

    async def attack(self, request: Request):
        self.finished = True
        request_to_root = Request(request.url)
        categories_file_path = os.path.join(self.user_config_dir, self.WAPP_CATEGORIES)
        groups_file_path = os.path.join(self.user_config_dir, self.WAPP_GROUPS)
        technologies_file_path = os.path.join(self.user_config_dir, self.WAPP_TECHNOLOGIES)

        await self._verify_wapp_database(categories_file_path, technologies_file_path, groups_file_path)

        try:
            application_data = ApplicationData(categories_file_path, groups_file_path, technologies_file_path)
        except FileNotFoundError as exception:
            logging.error(exception)
            logging.error(_("Try using --store-session option, or update apps.json using --update option."))
            return
        except ApplicationDataException as exception:
            logging.error(exception)
            return

        try:
            response = await self.crawler.async_send(request_to_root, follow_redirects=True)
        except RequestError:
            self.network_errors += 1
            return

        wappalyzer = Wappalyzer(application_data, response)
        detected_applications = wappalyzer.detect_with_versions_and_categories_and_groups()

        if len(detected_applications) > 0:
            log_blue("---")

        for application_name in sorted(detected_applications, key=lambda x: x.lower()):

            versions = detected_applications[application_name]["versions"]
            categories = detected_applications[application_name]["categories"]
            groups = detected_applications[application_name]["groups"]

            log_blue(MSG_TECHNO_VERSIONED, application_name, versions)
            log_blue(MSG_CATEGORIES, categories)
            log_blue(MSG_GROUPS, groups)
            log_blue("")
            await self.add_addition(
                category=TECHNO_DETECTED,
                request=request_to_root,
                info=json.dumps(detected_applications[application_name])
            )

            if versions:
                if "Web servers" in categories:
                    await self.add_vuln_info(
                        category=WEB_SERVER_VERSIONED,
                        request=request_to_root,
                        info=json.dumps(detected_applications[application_name])
                    )
                else:
                    await self.add_vuln_info(
                        category=WEB_APP_VERSIONED,
                        request=request_to_root,
                        info=json.dumps(detected_applications[application_name])
                    )

    async def _dump_url_content_to_file(self, url: str, file_path: str):
        request = Request(url)
        response = await self.crawler.async_send(request)

        with open(file_path, 'w', encoding='utf-8') as file:
            json.dump(response.json, file)

    async def _load_wapp_database(self, categories_url: str, technologies_base_url: str, groups_url: str):
        categories_file_path = os.path.join(self.user_config_dir, self.WAPP_CATEGORIES)
        groups_file_path = os.path.join(self.user_config_dir, self.WAPP_GROUPS)
        technologies_file_path = os.path.join(self.user_config_dir, self.WAPP_TECHNOLOGIES)
        technologie_files_name = list(map(lambda file_name: file_name + ".json", list("_" + string.ascii_lowercase)))
        technologies = {}

        # Requesting all technologies one by one
        for technologie_file_name in technologie_files_name:
            request = Request(technologies_base_url + technologie_file_name)
            response: Page = await self.crawler.async_send(request)
            # Merging all technologies in one object
            for technologie_name in response.json:
                technologies[technologie_name] = response.json[technologie_name]

        # Saving categories & groups
        await asyncio.gather(
            self._dump_url_content_to_file(categories_url, categories_file_path),
            self._dump_url_content_to_file(groups_url, groups_file_path)
        )

        # Saving technologies
        with open(technologies_file_path, 'w', encoding='utf-8') as file:
            json.dump(technologies, file)

    async def _verify_wapp_database(
            self,
            categories_file_path: str,
            technologies_base_path: str,
            groups_file_path: str
    ):
        try:
            with open(categories_file_path, encoding='utf-8') as categories_file, \
                    open(technologies_base_path, encoding='utf-8') as technologies_file, \
                    open(groups_file_path, encoding='utf-8') as groups_file:
                json.load(categories_file)
                json.load(technologies_file)
                json.load(groups_file)
        except IOError:
            logging.warning(_("Problem with local wapp database."))
            logging.info(_("Downloading from the web..."))
            await self.update()
