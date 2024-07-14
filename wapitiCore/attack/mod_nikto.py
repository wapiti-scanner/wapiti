#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2009-2023 Nicolas Surribas
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
import csv
import os
import random
import re
from typing import List, Optional
from urllib.parse import urlparse

from httpx import RequestError

from wapitiCore.main.log import logging, log_verbose, log_red
from wapitiCore.attack.attack import Attack, random_string
from wapitiCore.definitions.dangerous_resource import DangerousResourceFinding
from wapitiCore.net import Request, Response


# Nikto databases are csv files with the following fields (in order) :
#
#  1 - A unique identifier (number)
#  2 - The OSVDB reference number of the vulnerability
#  3 - Unknown (not used by Wapiti)
#  4 - The URL to check for. May contain a pattern to replace (eg: @CGIDIRS)
#  5 - The HTTP method to use when requesting the URL
#  6 - The HTTP status code returned when the vulnerability may exist
#      or a string the HTTP response may contain.
#  7 - Another condition for a possible vulnerability (6 OR 7)
#  8 - Another condition (must match for a possible vulnerability)
#  9 - A condition corresponding to an unexploitable webpage
# 10 - Another condition just like 9
# 11 - A description of the vulnerability with possible BID, CVE or MS references
# 12 - A url-form-encoded string (usually for POST requests)
#
# A possible vulnerability is reported in the following condition :
# ((6 or 7) and 8) and not (9 or 10)


class ModuleNikto(Attack):
    """
    Perform a brute-force attack to uncover known and potentially dangerous scripts on the web server.
    """

    nikto_db = []

    name = "nikto"
    NIKTO_DB = "nikto_db"
    NIKTO_DB_URL = "https://raw.githubusercontent.com/wapiti-scanner/nikto/master/program/databases/db_tests"

    user_config_dir = None
    finished = False

    def __init__(self, crawler, persister, attack_options, stop_event, crawler_configuration):
        Attack.__init__(self, crawler, persister, attack_options, stop_event, crawler_configuration)
        self.user_config_dir = self.persister.CONFIG_DIR
        self.junk_string = "w" + "".join(
            [random.choice("0123456789abcdefghjijklmnopqrstuvwxyz") for __ in range(0, 5000)]
        )
        self.parts = None

        if not os.path.isdir(self.user_config_dir):
            os.makedirs(self.user_config_dir)

        self.status_codes = {}
        self.random_string = random_string()

    async def update(self):
        """Update the Nikto database from the web and load the patterns."""
        try:
            request = Request(self.NIKTO_DB_URL)
            response = await self.crawler.async_send(request)

            csv.register_dialect("nikto", quoting=csv.QUOTE_ALL, doublequote=False, escapechar="\\")
            reader = csv.reader(response.content.split("\n"), "nikto")
            self.nikto_db = [line for line in reader if line != [] and line[0].isdigit()]

            with open(
                os.path.join(self.user_config_dir, self.NIKTO_DB),
                "w",
                errors="ignore",
                encoding='utf-8'
            ) as nikto_db_file:
                writer = csv.writer(nikto_db_file)
                writer.writerows(self.nikto_db)

        except IOError:
            logging.error("Error downloading nikto database.")

    async def must_attack(self, request: Request, response: Optional[Response] = None):
        if self.finished:
            return False

        if response.is_directory_redirection:
            return False

        return request.url == await self.persister.get_root_url()

    async def is_false_positive(self, evil_request: Request, expected_status_codes: List[int]) -> bool:
        # Check for false positives by asking an improbable file of the same type at the root of the server
        # Use a dict to cache requests
        if evil_request.is_directory:
            request = Request(f"{evil_request.root}{self.random_string}/")
        else:
            request = Request(f"{evil_request.root}{self.random_string}{evil_request.file_ext}")

        if request.path not in self.status_codes:
            try:
                response = await self.crawler.async_send(request)
            except RequestError:
                self.network_errors += 1
                # Do not put anything in cache, another luck for next time
                return False

            self.status_codes[request.path] = response.status

        return self.status_codes[request.path] in expected_status_codes

    async def attack(self, request: Request, response: Optional[Response] = None):
        try:
            with open(os.path.join(self.user_config_dir, self.NIKTO_DB), encoding='utf-8') as nikto_db_file:
                reader = csv.reader(nikto_db_file)
                next(reader)
                self.nikto_db = [line for line in reader if line != [] and line[0].isdigit()]

        except IOError:
            logging.warning("Problem with local nikto database.")
            logging.info("Downloading from the web...")
            await self.update()

        self.finished = True
        root_url = request.url
        self.parts = urlparse(root_url)

        tasks = set()
        pending_count = 0

        with open(os.path.join(self.user_config_dir, self.NIKTO_DB), encoding='utf-8') as nikto_db_file:
            reader = csv.reader(nikto_db_file)
            while True:

                if pending_count < self.options["tasks"] and not self._stop_event.is_set():
                    try:
                        line = next(reader)
                    except StopIteration:
                        pass
                    else:
                        if line == [] or not line[0].isdigit():
                            continue

                        task = asyncio.create_task(self.process_line(line))
                        tasks.add(task)

                if not tasks:
                    break

                done_tasks, pending_tasks = await asyncio.wait(
                    tasks,
                    timeout=0.01,
                    return_when=asyncio.FIRST_COMPLETED
                )
                pending_count = len(pending_tasks)
                for task in done_tasks:
                    await task
                    tasks.remove(task)

                if self._stop_event.is_set():
                    for task in pending_tasks:
                        task.cancel()
                        tasks.remove(task)

    async def process_line(self, line):
        match = match_or = match_and = False
        fail = fail_or = False

        osv_id = line[1]
        path = line[3]
        method = line[4]
        vuln_desc = line[10]
        post_data = line[11]

        path = path.replace("@CGIDIRS", "/cgi-bin/")
        path = path.replace("@ADMIN", "/admin/")
        path = path.replace("@NUKE", "/modules/")
        path = path.replace("@PHPMYADMIN", "/phpMyAdmin/")
        path = path.replace("@POSTNUKE", "/postnuke/")
        path = re.sub(r"JUNK\((\d+)\)", lambda x: self.junk_string[:int(x.group(1))], path)

        if path[0] == "@":
            return

        if not path.startswith("/"):
            path = "/" + path

        try:
            url = f"{self.parts.scheme}://{self.parts.netloc}{path}"
        except UnicodeDecodeError:
            return

        if method == "GET":
            evil_request = Request(url)
        elif method == "POST":
            evil_request = Request(url, post_params=post_data, method=method)
        else:
            evil_request = Request(url, post_params=post_data, method=method)

        if method == "GET":
            log_verbose(f"[¨] {evil_request.url}")
        else:
            log_verbose(f"[¨] {evil_request.http_repr()}")

        try:
            response = await self.crawler.async_send(evil_request)
            page = response.content
            code = response.status
        except (RequestError, ConnectionResetError):
            self.network_errors += 1
            return
        except Exception as exception:
            logging.warning(f"{exception} occurred with URL {evil_request.url}")
            return

        raw = " ".join([x + ": " + y for x, y in response.headers.items()])
        raw += page

        # See https://github.com/sullo/nikto/blob/master/program/plugins/nikto_tests.plugin for reference
        expected_status_codes = []
        # First condition (match)
        if len(line[5]) == 3 and line[5].isdigit():
            expected_status_code = int(line[5])
            expected_status_codes.append(expected_status_code)
            if code == expected_status_code:
                match = True
        else:
            if line[5] in raw:
                match = True

        # Second condition (or)
        if line[6] != "":
            if len(line[6]) == 3 and line[6].isdigit():
                expected_status_code = int(line[6])
                expected_status_codes.append(expected_status_code)
                if code == expected_status_code:
                    match_or = True
            else:
                if line[6] in raw:
                    match_or = True

        # Third condition (and)
        if line[7] != "":
            if len(line[7]) == 3 and line[7].isdigit():
                if code == int(line[7]):
                    match_and = True
            else:
                if line[7] in raw:
                    match_and = True
        else:
            match_and = True

        # Fourth condition (fail)
        if line[8] != "":
            if len(line[8]) == 3 and line[8].isdigit():
                if code == int(line[8]):
                    fail = True
            else:
                if line[8] in raw:
                    fail = True

        # Fifth condition (or)
        if line[9] != "":
            if len(line[9]) == 3 and line[9].isdigit():
                if code == int(line[9]):
                    fail_or = True
            else:
                if line[9] in raw:
                    fail_or = True

        if ((match or match_or) and match_and) and not (fail or fail_or):
            if expected_status_codes:
                if await self.is_false_positive(evil_request, expected_status_codes):
                    return

            log_red("---")
            log_red(vuln_desc)
            log_red(url)

            refs = []
            if osv_id != "0":
                refs.append("https://vulners.com/osvdb/OSVDB:" + osv_id)

            # CERT
            cert_advisory = re.search("(CA-[0-9]{4}-[0-9]{2})", vuln_desc)
            if cert_advisory is not None:
                refs.append("http://www.cert.org/advisories/" + cert_advisory.group(0) + ".html")

            # SecurityFocus
            securityfocus_bid = re.search("BID-([0-9]{4})", vuln_desc)
            if securityfocus_bid is not None:
                refs.append("http://www.securityfocus.com/bid/" + securityfocus_bid.group(1))

            # Mitre.org
            mitre_cve = re.search("((CVE|CAN)-[0-9]{4}-[0-9]{4,})", vuln_desc)
            if mitre_cve is not None:
                refs.append("http://cve.mitre.org/cgi-bin/cvename.cgi?name=" + mitre_cve.group(0))

            # CERT Incidents
            cert_incident = re.search("(IN-[0-9]{4}-[0-9]{2})", vuln_desc)
            if cert_incident is not None:
                refs.append("http://www.cert.org/incident_notes/" + cert_incident.group(0) + ".html")

            # Microsoft Technet
            ms_bulletin = re.search("(MS[0-9]{2}-[0-9]{3})", vuln_desc)
            if ms_bulletin is not None:
                refs.append("http://www.microsoft.com/technet/security/bulletin/" + ms_bulletin.group(0) + ".asp")

            info = vuln_desc
            if refs:
                log_red("References:")
                log_red("  " + "\n  ".join(refs))

                info += "\nReferences: \n"
                info += "\n".join(refs)

            log_red("---")

            await self.add_high(
                finding_class=DangerousResourceFinding,
                request=evil_request,
                info=info,
                response=response
            )
