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
from typing import Dict, List

from hashtheplanet.core.hashtheplanet import HashThePlanet
from httpx import RequestError
from wapitiCore.attack.attack import Attack
from wapitiCore.definitions.fingerprint_webserver import \
    NAME as WEB_SERVER_VERSIONED
from wapitiCore.language.vulnerability import _
from wapitiCore.main.log import log_blue
from wapitiCore.net.web import Request

MSG_TECHNO_VERSIONED = _("Range for {0} is from {1} to {2}")

# types
Technology = str
Version = str

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
        self.tech_versions: Dict[Technology, List[Version]] = {}
        self.user_config_dir = self.persister.CONFIG_DIR

        if not os.path.isdir(self.user_config_dir):
            os.makedirs(self.user_config_dir)

        self._htp = HashThePlanet(os.path.join(self.user_config_dir, self.HTP_DATABASE), "")

    async def must_attack(self, request: Request):
        if request.method == "POST":
            return False
        return True

    async def attack(self, request: Request):
        root_url = await self.persister.get_root_url()
        if request.url == root_url:
            files = self._htp.get_static_files()

            for file_path in files:
                await self._analyze_file(Request(root_url + file_path, method="GET"))
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
        if response.content is None or len(response.content) == 0:
            return
        content_hash = self._htp.analyze_str(response.content)
        if content_hash is not None:
            technology = content_hash[0]
            tech_info = json.loads(content_hash[1])

            if self.tech_versions.get(technology) is None:
                self.tech_versions[technology] = []
            self.tech_versions[technology].append(tech_info["versions"])

    async def finish(self):
        root_url = await self.persister.get_root_url()
        truth_table: List[Version] = None
        ranges_tables = None

        for technology, versions_list in self.tech_versions.items():
            # First we retrieve all the stored versions in the same order as they have been added to the database
            truth_table = self._htp.get_versions(technology)
            ranges_tables = []

            # We create ranges of versions by using the index of the version in the truth table
            for versions in versions_list:
                ranges_tables.append([truth_table.index(versions[0]), truth_table.index(versions[len(versions) - 1])])

            # We obtain the list of min range values by only keeping the first value
            min_range = list(map(lambda arr: arr[0], ranges_tables))

            # We obtain the list of max range values by only keeping the last value
            max_range = list(map(lambda arr: arr[len(arr) - 1], ranges_tables))

            # We get the min range by sorting the ranges by ascending order and retrieving the first value
            min_index = sorted(min_range)[0]

            # We get the max range by sorting the ranges by descending order and retrieving the first value
            max_index = sorted(max_range, reverse=True)[0]

            tech_info = {}
            tech_info["name"] = technology
            tech_info["versions"] = truth_table[min_index:max_index + 1]

            await self.add_vuln_info(
                category=WEB_SERVER_VERSIONED,
                request=Request(root_url),
                info=json.dumps(tech_info)
            )
            log_blue(MSG_TECHNO_VERSIONED, technology, truth_table[min_index], truth_table[max_index])
        self.finished = True
