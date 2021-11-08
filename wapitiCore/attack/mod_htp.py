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

from hashtheplanet.core.hashtheplanet import HashThePlanet
from httpx import RequestError
from wapitiCore.attack.attack import Attack
from wapitiCore.definitions.fingerprint_webserver import \
    NAME as WEB_SERVER_VERSIONED
from wapitiCore.language.vulnerability import _
from wapitiCore.main.log import log_blue
from wapitiCore.net import web
from wapitiCore.net.web import Request

MSG_TECHNO_VERSIONED = _("{0} {1} detected")

class ModuleHtp(Attack):
    """
    Identify web technologies used by the web server using HashThePlanet database.
    """

    name = "htp"

    do_get = True
    do_post = False
    user_config_dir = None
    finished = False

    HTP_DATABASE = "hashtheplanet.db"

    def __init__(self, crawler, persister, attack_options, stop_event):
        Attack.__init__(self, crawler, persister, attack_options, stop_event)
        self.user_config_dir = self.persister.CONFIG_DIR

        if not os.path.isdir(self.user_config_dir):
            os.makedirs(self.user_config_dir)

        self._htp = HashThePlanet(os.path.join(self.user_config_dir, self.HTP_DATABASE))

    async def must_attack(self, request: Request):
        if request.method == "POST":
            return False
        return True

    async def attack(self, request: Request):
        self.finished = True

        root_url = await self.persister.get_root_url()
        if request.url == root_url:
            files = self._htp.get_static_files()

            for file_path in files:
                await self._analyze_file(web.Request(root_url + file_path))
        await self._analyze_file(request)

    async def _analyze_file(self, request: Request):
        """
        Retrieves the url's content and then analyze it to get the technology and the version
        """
        try:
            response = await self.crawler.async_send(request, follow_redirects=True)
        except RequestError:
            self.network_errors += 1
            return
        content_hash = self._htp.analyze_str(response.content.encode('utf-8'))
        if content_hash is not None:
            result = json.loads(content_hash[1])
            result["name"] = content_hash[0]

            await self.add_vuln_info(
                category=WEB_SERVER_VERSIONED,
                request=request,
                info=json.dumps(result)
            )
            log_blue(MSG_TECHNO_VERSIONED, content_hash[0], content_hash[1])
