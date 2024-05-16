#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2023-2024 Cyberwatch
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
from os.path import join as path_join

from typing import Tuple
from httpx import RequestError

from wapitiCore.attack.attack import Attack
from wapitiCore.net import Request
from wapitiCore.net.response import Response

MSG_TECHNO_VERSIONED = "{0} {1} detected"


def calculate_git_hash(file_content):
    # Calculate the size of the file
    file_size = len(file_content)
    # Create the string to hash to match the git hash function
    to_hash = b"blob " + str(file_size).encode() + b"\0" + file_content
    git_hash = hashlib.sha1(to_hash).hexdigest()
    return git_hash


class CommonCMS(Attack):
    """Base class for CMS detecting version."""
    name = "cms"
    versions = []

    def get_hashes(self, payloads_hash):
        with open(path_join(self.DATA_DIR, payloads_hash), errors="ignore", encoding='utf-8') as hashes:
            data = json.load(hashes)
            return data

    async def get_url_hash(self, root_url: str, path: str) -> Tuple[str, str]:
        request = Request(f"{root_url}{path}", "GET")
        response: Response = await self.crawler.async_send(request, follow_redirects=True)
        if response.is_error:
            return "", ""

        file_content = response.bytes
        git_hash = calculate_git_hash(file_content)
        return git_hash, path

    async def detect_version(self, payloads_hash, root_url):
        versions = {}
        detection_db = self.get_hashes(payloads_hash)
        tasks = set()

        for path in detection_db:
            task = asyncio.create_task(self.get_url_hash(root_url, path))
            tasks.add(task)

            while tasks:
                done_tasks, pending_tasks = await asyncio.wait(
                    tasks,
                    timeout=0.01,
                    return_when=asyncio.FIRST_COMPLETED
                )

                for task in done_tasks:
                    try:
                        content_hash, path = await task
                    except RequestError:
                        self.network_errors += 1
                    else:
                        if content_hash and content_hash in detection_db[path]:
                            versions[path] = detection_db[path][content_hash]

                    tasks.remove(task)

                if self._stop_event.is_set():
                    for task in pending_tasks:
                        task.cancel()
                        tasks.remove(task)

                if len(pending_tasks) > self.options["tasks"]:
                    continue

                break

            if self._stop_event.is_set():
                break

        # We reached the end of your list, but we may still have some running tasks
        while tasks:
            done_tasks, pending_tasks = await asyncio.wait(
                tasks,
                timeout=0.01,
                return_when=asyncio.FIRST_COMPLETED
            )

            for task in done_tasks:
                try:
                    content_hash, path = await task
                except RequestError:
                    self.network_errors += 1
                else:
                    if content_hash and content_hash in detection_db[path]:
                        versions[path] = detection_db[path][content_hash]

                tasks.remove(task)

            if self._stop_event.is_set():
                for task in pending_tasks:
                    task.cancel()
                    tasks.remove(task)

                break

        if versions:
            self.versions = set.intersection(*[set(versions) for versions in versions.values()])
