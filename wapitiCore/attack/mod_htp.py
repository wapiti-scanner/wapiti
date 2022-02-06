import hashlib
import json
import os
import re
import sqlite3
from typing import Dict, List, Tuple

from httpx import RequestError
from wapitiCore.attack.attack import Attack
from wapitiCore.definitions.fingerprint_webserver import \
    NAME as WEB_SERVER_VERSIONED
from wapitiCore.language.vulnerability import _
from wapitiCore.main.log import log_blue, logging
from wapitiCore.net.page import Page
from wapitiCore.net.web import Request

MSG_TECHNO_VERSIONED = _("The range for {0} is from {1} to {2}")

# types
Technology = str
Version = str


class ModuleHtp(Attack):
    """
    Identify web technologies used by the web server using the HashThePlanet database.
    """

    name = "htp"

    do_get = True
    do_post = False
    user_config_dir = None
    finished = False
    _db = None

    HTP_DATABASE = "hashtheplanet.db"
    HTP_DATABASE_URL = "https://github.com/Cyberwatch/HashThePlanet/releases/download/latest/hashtheplanet.db"

    def __init__(self, crawler, persister, attack_options, stop_event):
        Attack.__init__(self, crawler, persister, attack_options, stop_event)
        self.tech_versions: Dict[Technology, List[Version]] = {}
        self.user_config_dir = self.persister.CONFIG_DIR

        if not os.path.isdir(self.user_config_dir):
            os.makedirs(self.user_config_dir)

    async def update(self):
        """Update the HashThePlanet database from the web."""
        try:
            await self._download_htp_database(
                self.HTP_DATABASE_URL,
                os.path.join(self.user_config_dir, self.HTP_DATABASE)
            )
        except IOError:
            logging.error(_("Error downloading htp database."))

    async def must_attack(self, request: Request):
        if request.method == "POST":
            return False
        return True

    async def attack(self, request: Request):
        await self._init_db()
        root_url = await self.persister.get_root_url()

        if request.url == root_url:
            files = self._get_static_files()

            for file_path in files:
                await self._analyze_file(Request(root_url + file_path, method="GET"))
        await self._analyze_file(request)

    async def _init_db(self):
        if self._db is None:
            await self._verify_htp_database(os.path.join(self.user_config_dir, self.HTP_DATABASE))
            self._db = sqlite3.connect(os.path.join(self.user_config_dir, self.HTP_DATABASE))
            self._db.create_function("REGEXP", 2, regexp)

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
        found_technology = self._find_technology(response.bytes)
        if found_technology is not None:
            technology_name = found_technology[0]
            technology_info = json.loads(found_technology[1])

            if self.tech_versions.get(technology_name) is None:
                self.tech_versions[technology_name] = []

            self.tech_versions[technology_name].append(json.loads(technology_info)["versions"])

    async def finish(self):
        if self._db is None:
            return

        root_url = await self.persister.get_root_url()

        for technology, versions_list in self.tech_versions.items():
            # First we retrieve all the stored versions in the same order as they have been added to the database
            truth_table = self._get_versions(technology)
            ranges_tables = []

            # We create ranges of versions by using the index of the version in the truth table
            for versions in versions_list:
                ranges_tables.append([truth_table.index(versions[0]), truth_table.index(versions[len(versions) - 1])])

            # We obtain the list of min range values by only keeping the first value
            min_range = [arr[0] for arr in ranges_tables]

            # We obtain the list of max range values by only keeping the last value
            max_range = [arr[len(arr) - 1] for arr in ranges_tables]

            # We get the min range by sorting the ranges by ascending order and retrieving the first value
            min_index = sorted(min_range)[0]

            # We get the max range by sorting the ranges by descending order and retrieving the first value
            max_index = sorted(max_range, reverse=True)[0]

            tech_info = {
                "name": technology,
                "versions": truth_table[min_index:max_index + 1]
            }

            await self.add_vuln_info(
                category=WEB_SERVER_VERSIONED,
                request=Request(root_url),
                info=json.dumps(tech_info)
            )
            log_blue(MSG_TECHNO_VERSIONED, technology, truth_table[min_index], truth_table[max_index])
        self._db.close()
        self.finished = True

    def _find_technology(self, page_content: bytes) -> Tuple[str, str]:
        cursor = self._db.cursor()
        page_hash = hashlib.sha256(page_content).hexdigest()
        stmt = "SELECT `technology`, `versions` FROM `Hash` WHERE `hash`=:hash"

        result = cursor.execute(stmt, {"hash": page_hash}).fetchone()
        cursor.close()
        return result

    def _get_versions(self, technology: str) -> List[str]:
        cursor = self._db.cursor()
        stmt = "SELECT `version` FROM `Version` WHERE `technology`=:technology ORDER BY rowid ASC"

        result = cursor.execute(stmt, {"technology": technology}).fetchall()
        cursor.close()
        return [version[0] for version in result]

    def _get_static_files(self) -> List[str]:
        cursor = self._db.cursor()
        query_regexp = r"([a-zA-Z0-9\s_\\.\-\(\):])+(.html|.md|.txt|.css)$"
        stmt = f"SELECT `path` FROM `File` WHERE `path` REGEXP \'{query_regexp}\'"

        result = cursor.execute(stmt).fetchall()
        cursor.close()
        return [path for path, in result]

    async def _download_htp_database(self, htp_dabatabse_url: str, htp_database_path: str):
        request = Request(htp_dabatabse_url)
        response: Page = await self.crawler.async_send(request, follow_redirects=True)

        with open(htp_database_path, 'wb') as file:
            file.write(response.bytes)

    async def _verify_htp_database(self, htp_database_path: str):
        if os.path.exists(htp_database_path) is False:
            logging.warning(_("Problem with local htp database."))
            logging.info(_("Downloading from the web..."))
            await self.update()


def regexp(expr, item):
    reg = re.compile(expr)

    return reg.search(item) is not None
