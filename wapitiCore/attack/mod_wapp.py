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

from httpx import RequestError

from wapitiCore.main.log import logging, log_blue
from wapitiCore.attack.attack import Attack
from wapitiCore.wappalyzer.wappalyzer import Wappalyzer, ApplicationData, ApplicationDataException
from wapitiCore.language.vulnerability import _
from wapitiCore.definitions.fingerprint import NAME as TECHNO_DETECTED
from wapitiCore.definitions.fingerprint_webserver import NAME as WEB_SERVER_VERSIONED
from wapitiCore.definitions.fingerprint_webapp import NAME as WEB_APP_VERSIONED
from wapitiCore.net.web import Request

MSG_TECHNO_VERSIONED = _("{0} {1} detected")


class mod_wapp(Attack):
    """
    Identify web technologies used by the web server using Wappalyzer database.
    """

    name = "wapp"
    WAPP_DB = "apps.json"
    WAPP_DB_URL = "https://raw.githubusercontent.com/wapiti-scanner/wappalyzer/master/src/technologies.json"

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
            request = Request(self.WAPP_DB_URL)
            response = await self.crawler.async_send(request)

            with open(os.path.join(self.user_config_dir, self.WAPP_DB), 'w', encoding='utf-8') as wapp_db_file:
                json.dump(response.json, wapp_db_file)

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

        try:
            with open(os.path.join(self.user_config_dir, self.WAPP_DB), encoding='utf-8') as wapp_db_file:
                json.load(wapp_db_file)
        except IOError:
            logging.warning(_("Problem with local wapp database."))
            logging.info(_("Downloading from the web..."))
            await self.update()

        try:
            application_data = ApplicationData(os.path.join(self.user_config_dir, self.WAPP_DB))
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
        detected_applications = wappalyzer.detect_with_versions_and_categories()

        if len(detected_applications) > 0:
            log_blue("---")

        for application_name in sorted(detected_applications, key=lambda x: x.lower()):

            versions = detected_applications[application_name]["versions"]
            categories = detected_applications[application_name]["categories"]

            log_blue(
                MSG_TECHNO_VERSIONED,
                application_name,
                versions
            )

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
