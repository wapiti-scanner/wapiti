#!/usr/bin/env python3
# This file is part of the Wapiti project (http://wapiti.sourceforge.io)
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

from wapitiCore.attack.attack import Attack
from wapitiCore.wappalyzer.wappalyzer import Wappalyzer, ApplicationData, ApplicationDataException
from wapitiCore.language.vulnerability import Additional, _
from wapitiCore.net.web import Request


class mod_wapp(Attack):
    """
    Identify web technologies used by the web server using Wappalyzer database.
    """

    name = "wapp"
    WAPP_DB = "apps.json"
    WAPP_DB_URL = "https://raw.githubusercontent.com/AliasIO/wappalyzer/master/src/technologies.json"

    do_get = False
    do_post = False

    def __init__(self, crawler, persister, logger, attack_options):
        Attack.__init__(self, crawler, persister, logger, attack_options)
        user_config_dir = self.CONFIG_DIR

        if not os.path.isdir(user_config_dir):
            os.makedirs(user_config_dir)
        try:
            with open(os.path.join(user_config_dir, self.WAPP_DB)) as wapp_db_file:
                json.load(wapp_db_file)

        except IOError:
            print(_("Problem with local wapp database."))
            print(_("Downloading from the web..."))
            self.update()

    def update(self):
        try:
            request = Request(self.WAPP_DB_URL)
            response = self.crawler.send(request)

            with open(os.path.join(self.CONFIG_DIR, self.WAPP_DB), 'w') as wapp_db_file:
                json.dump(response.json, wapp_db_file)

        except IOError:
            print(_("Error downloading wapp database."))

    def attack(self):
        url = self.persister.get_root_url()
        request = Request(url)
        if self.verbose >= 1:
            print("[+] {}".format(request))

        try:
            application_data = ApplicationData(os.path.join(self.CONFIG_DIR, self.WAPP_DB))
        except FileNotFoundError as exception:
            print(exception)
            print(_("Try using --store-session option, or update apps.json using --update option."))
            return
        except ApplicationDataException as exception:
            print(exception)
            return

        response = self.crawler.send(request, follow_redirects=True)
        wappalyzer = Wappalyzer(application_data, response)
        detected_applications = wappalyzer.detect_with_versions_and_categories()

        if len(detected_applications) > 0:
            self.log_blue("---")

        for application_name in sorted(detected_applications, key=lambda x: x.lower()):
                self.log_blue(Additional.MSG_TECHNO_VERSIONED, application_name,
                              detected_applications[application_name]["versions"])
                self.add_addition(
                    category=Additional.TECHNO_DETECTED,
                    level=Additional.LOW_LEVEL,
                    request=request,
                    info=json.dumps(detected_applications[application_name])
                    )
        yield
