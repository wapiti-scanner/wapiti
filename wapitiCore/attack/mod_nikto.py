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

    def __init__(self, crawler, persister, attack_options, crawler_configuration):
        Attack.__init__(self, crawler, persister, attack_options, crawler_configuration)
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

                if pending_count < self.options["tasks"]:
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

    async def process_line(self, line):
        # Extract data from line
        osv_id, path, method, vuln_desc, post_data = line[1], line[3], line[4], line[10], line[11]

        # Process path
        path = self._process_path(path)
        if path is None:
            return

        # Create request
        evil_request = self._create_request(path, method, post_data)
        if evil_request is None:
            return

        _log_request(evil_request, method)

        # Send request and get response
        response, _, code, raw = await self._send_request(evil_request)
        if response is None:
            return

        # Evaluate conditions
        match, match_or, match_and = _evaluate_match_conditions(line, code, raw)
        fail, fail_or = _evaluate_fail_conditions(line, code, raw)

        # Check if vulnerability is present
        if ((match or match_or) and match_and) and not (fail or fail_or):
            expected_status_codes = _get_expected_status_codes(line)
            if expected_status_codes and await self.is_false_positive(evil_request, expected_status_codes):
                return

            # Report vulnerability
            await self._report_vulnerability(evil_request, vuln_desc, osv_id, response)

    def _process_path(self, path):
        """Process the path by replacing placeholders"""
        replacements = {
            "@CGIDIRS": "/cgi-bin/",
            "@ADMIN": "/admin/",
            "@NUKE": "/modules/",
            "@PHPMYADMIN": "/phpMyAdmin/",
            "@POSTNUKE": "/postnuke/"
        }

        for placeholder, replacement in replacements.items():
            path = path.replace(placeholder, replacement)

        # Handle JUNK replacement
        path = re.sub(r"JUNK\((\d+)\)", lambda x: self.junk_string[:int(x.group(1))], path)

        if path[0] == "@":
            return None

        if not path.startswith("/"):
            path = "/" + path

        return path

    def _create_request(self, path, method, post_data):
        """Create request object based on method and data"""
        try:
            url = f"{self.parts.scheme}://{self.parts.netloc}{path}"
        except UnicodeDecodeError:
            return None

        if method == "GET":
            return Request(url)

        return Request(url, post_params=post_data, method=method)

    async def _send_request(self, request):
        """Send the request and handle errors"""
        try:
            response = await self.crawler.async_send(request)
            page = response.content
            code = response.status
            raw = " ".join([f"{x}: {y}" for x, y in response.headers.items()]) + page
            return response, page, code, raw
        except (RequestError, ConnectionResetError):
            self.network_errors += 1
            return None, None, None, None
        except Exception as exception:  # pylint: disable=broad-except
            logging.warning(f"{exception} occurred with URL {request.url}")
            return None, None, None, None

    async def _report_vulnerability(self, request, vuln_desc, osv_id, response):
        """Report found vulnerability"""
        log_red("---")
        log_red(vuln_desc)
        log_red(request.url)

        refs = _collect_references(osv_id, vuln_desc)

        info = vuln_desc
        if refs:
            log_red("References:")
            log_red("  " + "\n  ".join(refs))

            info += "\nReferences: \n"
            info += "\n".join(refs)

        log_red("---")

        await self.add_high(
            finding_class=DangerousResourceFinding,
            request=request,
            info=info,
            response=response
        )


def _log_request(request, method):
    """Log the request details"""
    if method == "GET":
        log_verbose(f"[¨] {request.url}")
    else:
        log_verbose(f"[¨] {request.http_repr()}")


def _evaluate_match_conditions(line, code, raw):
    """Evaluate the match conditions"""
    match = match_or = False
    match_and = True  # Default to True if line[7] is empty

    # First condition (match)
    if len(line[5]) == 3 and line[5].isdigit():
        if code == int(line[5]):
            match = True
    elif line[5] in raw:
        match = True

    # Second condition (or)
    if line[6]:
        if len(line[6]) == 3 and line[6].isdigit():
            if code == int(line[6]):
                match_or = True
        elif line[6] in raw:
            match_or = True

    # Third condition (and)
    if line[7]:
        if len(line[7]) == 3 and line[7].isdigit():
            match_and = code == int(line[7])
        else:
            match_and = line[7] in raw

    return match, match_or, match_and

def _evaluate_fail_conditions(line, code, raw):
    """Evaluate the fail conditions"""
    fail = fail_or = False

    # Fourth condition (fail)
    if line[8]:
        if len(line[8]) == 3 and line[8].isdigit():
            fail = code == int(line[8])
        else:
            fail = line[8] in raw

    # Fifth condition (or)
    if line[9]:
        if len(line[9]) == 3 and line[9].isdigit():
            fail_or = code == int(line[9])
        else:
            fail_or = line[9] in raw

    return fail, fail_or

def _get_expected_status_codes(line):
    """Extract expected status codes from conditions"""
    expected_status_codes = []

    if len(line[5]) == 3 and line[5].isdigit():
        expected_status_codes.append(int(line[5]))

    if line[6] and len(line[6]) == 3 and line[6].isdigit():
        expected_status_codes.append(int(line[6]))

    return expected_status_codes


def _collect_references(osv_id, vuln_desc):
    """Collect references for the vulnerability"""
    refs = []

    # OSVDB reference
    if osv_id != "0":
        refs.append(f"https://vulners.com/osvdb/OSVDB:{osv_id}")

    # Extract references from vulnerability description
    reference_patterns = [
        (r"(CA-[0-9]{4}-[0-9]{2})", "http://www.cert.org/advisories/{0}.html"),
        (r"BID-([0-9]{4})", "http://www.securityfocus.com/bid/{0}"),
        (r"((CVE|CAN)-[0-9]{4}-[0-9]{4,})", "http://cve.mitre.org/cgi-bin/cvename.cgi?name={0}"),
        (r"(IN-[0-9]{4}-[0-9]{2})", "http://www.cert.org/incident_notes/{0}.html"),
        (r"(MS[0-9]{2}-[0-9]{3})", "http://www.microsoft.com/technet/security/bulletin/{0}.asp")
    ]

    for pattern, url_template in reference_patterns:
        match = re.search(pattern, vuln_desc)
        if match:
            if '{0}' in url_template:
                refs.append(url_template.format(match.group(1)))
            else:
                refs.append(url_template.format(match.group(0)))

    return refs
