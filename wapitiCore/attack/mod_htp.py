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
import asyncio
import hashlib
import json
import os
import re
import sqlite3
from typing import Dict, List, Tuple, Optional
from itertools import chain

from httpx import RequestError
from wapitiCore.attack.attack import Attack
from wapitiCore.definitions.fingerprint_webserver import WebServerVersionDisclosureFinding
from wapitiCore.main.log import log_blue, logging
from wapitiCore.net.response import Response
from wapitiCore.net import Request

MSG_TECHNO_VERSIONS_RANGE = "Detected {0} technology seems to match versions from {1} to {2}"
MSG_TECHNO_SINGLE_VERSION = "Detected {0} technology seems to match version {1}"

# types
Technology = str
Versions = List[str]


def get_matching_versions(known_versions: Versions, possible_versions_list: List[Versions]) -> Versions:
    # Flatten the lists of list of version strings, make versions unique
    flat_versions = set(chain(*possible_versions_list))
    indexes = [known_versions.index(version) for version in flat_versions if version in known_versions]
    if not indexes:
        return []

    # Returns the range of versions that start at the lowest found version to the highest found version
    return known_versions[min(indexes):max(indexes)+1]


class ModuleHtp(Attack):
    """
    Identify web technologies used by the web server using the HashThePlanet database.
    """

    name = "htp"
    passive_scan_responses = False

    do_get = True
    do_post = False
    user_config_dir = None
    finished = False
    _db = None

    HTP_DATABASE = "hashtheplanet.db"
    # HashThePlanet no longer ships a prebuilt SQLite database. Each release now carries one JSON file per
    # technology (format_version 2), so the database is rebuilt locally from those files.
    HTP_RELEASE_API_URL = "https://api.github.com/repos/Cyberwatch/HashThePlanet/releases/latest"
    HTP_ASSET_SUFFIX = "_hash_files.json"

    def __init__(self, crawler, persister, attack_options, crawler_configuration):
        Attack.__init__(self, crawler, persister, attack_options, crawler_configuration)
        self.tech_versions: Dict[Technology, List[Versions]] = {}
        self.user_config_dir = self.persister.CONFIG_DIR

        if not os.path.isdir(self.user_config_dir):
            os.makedirs(self.user_config_dir)

    async def update(self):
        """Rebuild the HashThePlanet database from the per-technology JSON files of the latest release."""
        try:
            await self._build_htp_database(
                os.path.join(self.user_config_dir, self.HTP_DATABASE)
            )
        except (IOError, ValueError) as exception:
            logging.error("Error downloading htp database: %s", exception)

    async def must_attack(self, request: Request, response: Optional[Response] = None):
        if request.method == "POST":
            return False
        return True

    async def attack(self, request: Request, response: Optional[Response] = None):
        await self._init_db()
        root_url = await self.persister.get_root_url()

        if request.url == root_url:
            await self.search_static_files(root_url)

        found_technology = await self._analyze_file(request)
        if found_technology is not None:
            technology_name = found_technology[0]
            technology_info = json.loads(found_technology[1])

            if self.tech_versions.get(technology_name) is None:
                self.tech_versions[technology_name] = []

            self.tech_versions[technology_name].append(json.loads(technology_info)["versions"])

    async def search_static_files(self, root_url: str):
        files = self._get_static_files()
        tasks = set()

        for file_path in files:
            task = asyncio.create_task(self._analyze_file(Request(root_url + file_path, method="GET")))
            tasks.add(task)

            while tasks:
                done_tasks, pending_tasks = await asyncio.wait(
                    tasks,
                    timeout=0.01,
                    return_when=asyncio.FIRST_COMPLETED
                )

                for task in done_tasks:
                    found_technology = await task
                    if found_technology is not None:
                        technology_name = found_technology[0]
                        technology_info = json.loads(found_technology[1])

                        if self.tech_versions.get(technology_name) is None:
                            self.tech_versions[technology_name] = []

                        self.tech_versions[technology_name].append(json.loads(technology_info)["versions"])

                    tasks.remove(task)

                if len(pending_tasks) <= self.options["tasks"]:
                    break

        # We reached the end of your list, but we may still have some running tasks
        while tasks:
            done_tasks, pending_tasks = await asyncio.wait(
                tasks,
                timeout=0.01,
                return_when=asyncio.FIRST_COMPLETED
            )

            for task in done_tasks:
                found_technology = await task
                if found_technology is not None:
                    technology_name = found_technology[0]
                    technology_info = json.loads(found_technology[1])

                    if self.tech_versions.get(technology_name) is None:
                        self.tech_versions[technology_name] = []

                    self.tech_versions[technology_name].append(json.loads(technology_info)["versions"])

                tasks.remove(task)

    async def _init_db(self):
        if self._db is None:
            await self._verify_htp_database(os.path.join(self.user_config_dir, self.HTP_DATABASE))
            self._db = sqlite3.connect(
                f"file:{os.path.join(self.user_config_dir, self.HTP_DATABASE)}?mode=ro",
                uri=True,
            )
            self._db.create_function("REGEXP", 2, regexp)

    async def _analyze_file(self, request: Request) -> Optional[Tuple[str, str]]:
        """
        Retrieves the URL's content and then analyze it to get the technology and the version
        """
        try:
            response = await self.crawler.async_send(request, follow_redirects=True)
        except RequestError:
            self.network_errors += 1
            return

        if response.content is None or len(response.content) == 0:
            return

        return self._find_technology(response.bytes)

    async def finish(self):
        if self._db is None:
            return

        root_url = await self.persister.get_root_url()

        for technology, versions_list in self.tech_versions.items():
            # First we retrieve all the stored versions in the same order as they have been added to the database
            truth_table = self._get_versions(technology)
            matching_versions = get_matching_versions(truth_table, versions_list)
            if not matching_versions:
                continue

            tech_info = {
                "name": technology,
                "versions": matching_versions
            }

            await self.add_info(
                finding_class=WebServerVersionDisclosureFinding,
                request=Request(root_url),
                info=json.dumps(tech_info)
            )
            if len(matching_versions) > 1:
                log_blue(MSG_TECHNO_VERSIONS_RANGE, technology, matching_versions[0], matching_versions[-1])
            else:
                log_blue(MSG_TECHNO_SINGLE_VERSION, technology, matching_versions[0])

        self._db.close()
        self.finished = True

    def _find_technology(self, page_content: bytes) -> Optional[Tuple[str, str]]:
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

    async def _fetch_json(self, url: str) -> dict:
        """Download a URL and return its parsed JSON body, raising IOError on any HTTP error."""
        # allow_offsite_redirects: release downloads redirect to GitHub's CDN, outside the scan scope
        response: Response = await self.crawler.async_send(
            Request(url), follow_redirects=True, allow_offsite_redirects=True
        )

        if response.status != 200:
            raise IOError(f"Failed to download {url}: HTTP {response.status}")

        content = response.json
        if content is None:
            raise IOError(f"Failed to parse JSON from {url}")

        return content

    async def _get_release_asset_urls(self) -> List[str]:
        """List the download URLs of the per-technology JSON files of the latest release."""
        release = await self._fetch_json(self.HTP_RELEASE_API_URL)
        urls = [
            asset["browser_download_url"]
            for asset in release.get("assets", [])
            if asset.get("name", "").endswith(self.HTP_ASSET_SUFFIX)
        ]

        if not urls:
            raise IOError("No HashThePlanet hash file found in the latest release")

        return urls

    async def _build_htp_database(self, htp_database_path: str):
        """Download every technology hash file and (re)build the local SQLite database from them."""
        asset_urls = await self._get_release_asset_urls()

        tmp_path = htp_database_path + ".tmp"
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

        try:
            db = sqlite3.connect(tmp_path)
            try:
                db.executescript(
                    "CREATE TABLE Hash (hash TEXT, technology TEXT, versions TEXT);"
                    "CREATE TABLE Version (technology TEXT, version TEXT);"
                    "CREATE TABLE File (path TEXT);"
                )

                for url in asset_urls:
                    technology = os.path.basename(url)[: -len(self.HTP_ASSET_SUFFIX)]
                    self._insert_technology(db, technology, await self._fetch_json(url))

                # The hash lookup runs for every crawled file, the path lookup once per scan
                db.executescript(
                    "CREATE INDEX idx_hash ON Hash (hash);"
                    "CREATE INDEX idx_file_path ON File (path);"
                )
                db.commit()
            finally:
                db.close()
        except BaseException:
            # Leave the previous database in place and drop the half-written temporary file
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise

        # Replace the database in one step so a failed build never leaves a half-written file behind
        os.replace(tmp_path, htp_database_path)

    @staticmethod
    def _insert_technology(db: sqlite3.Connection, technology: str, hash_file: dict):
        """Fill the three tables from one technology JSON file (HashThePlanet format_version 2)."""
        versions = hash_file.get("_meta", {}).get("sorted_versions", [])
        # Version rows are read back in insertion order (rowid), so keep the sorted order of the file
        db.executemany(
            "INSERT INTO Version (technology, version) VALUES (?, ?)",
            [(technology, version) for version in versions],
        )

        hash_rows = []
        for path, hashes in hash_file.get("files", {}).items():
            db.execute("INSERT INTO File (path) VALUES (?)", (path,))
            for file_hash, file_versions in hashes.items():
                # The reader decodes this column twice (json.loads(json.loads(...))), so encode it twice
                encoded = json.dumps(json.dumps({"versions": file_versions}))
                hash_rows.append((file_hash, technology, encoded))

        db.executemany("INSERT INTO Hash (hash, technology, versions) VALUES (?, ?, ?)", hash_rows)

    async def _verify_htp_database(self, htp_database_path: str):
        needs_download = not os.path.exists(htp_database_path)

        if not needs_download:
            try:
                db = sqlite3.connect(f"file:{htp_database_path}?mode=ro", uri=True)
                db.execute("SELECT 1 FROM `Hash` LIMIT 1")
                db.close()
            except (sqlite3.OperationalError, sqlite3.DatabaseError):
                needs_download = True

        if needs_download:
            logging.warning("Problem with local htp database.")
            logging.info("Downloading from the web...")
            await self.update()


def regexp(expr, item):
    reg = re.compile(expr)

    return reg.search(item) is not None
