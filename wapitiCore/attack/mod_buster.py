#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2014-2023 Nicolas Surribas
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
from collections import defaultdict
from difflib import SequenceMatcher
from os.path import join as path_join
from typing import Optional

from httpx import RequestError

from wapitiCore.main.log import log_red, log_orange, log_verbose
from wapitiCore.attack.attack import Attack, random_string
from wapitiCore.net import Request, Response
from wapitiCore.definitions.buster import BusterFinding

# Above this similarity ratio, a candidate response is considered a mere copy of
# the server's generic "not found" page (soft 404).
SIMILARITY_THRESHOLD = 0.9


def responses_are_similar(response1: str, response2: str) -> bool:
    """Return True when the two response bodies are near-identical."""
    return SequenceMatcher(None, response1, response2).quick_ratio() > SIMILARITY_THRESHOLD


def is_false_positive(response: Response, not_found_response: Response) -> bool:
    """
    Return True when `response` merely replays the generic "not found" answer of the
    server, captured in `not_found_response` by requesting an improbable resource.

    This catches two common setups that would otherwise flood the results:
      - catch-all redirection: any unknown path is redirected to the same location;
      - soft 404: any unknown path returns a 200 with the same "not found" body.
    """
    # Catch-all redirection: both the improbable path and the candidate are
    # redirected to the very same location.
    if response.redirection_url and not_found_response.redirection_url:
        return response.redirection_url == not_found_response.redirection_url

    # Soft 404: same status code and a near-identical body as the improbable path.
    if not response.redirection_url and not not_found_response.redirection_url:
        return (
            response.status == not_found_response.status
            and responses_are_similar(response.content, not_found_response.content)
        )

    return False


class ModuleBuster(Attack):
    """
    Brute force paths on the web-server to discover hidden files and directories.
    """

    PATHS_FILE = "busterPayloads.txt"

    name = "buster"

    do_get = True
    do_post = False

    # Warn (once per host) only after that many HTTP 429/5xx responses, so a single
    # transient error does not trigger a false alarm.
    RATE_LIMIT_WARNING_THRESHOLD = 5

    def __init__(self, crawler, persister, attack_options, crawler_configuration):
        Attack.__init__(self, crawler, persister, attack_options, crawler_configuration)
        self.known_dirs = []
        self.known_pages = []
        self.new_resources = []
        self.network_errors = 0
        self.server_error_counts = defaultdict(int)
        self.rate_limited_netlocs = set()

    def warn_on_rate_limiting(self, request: Request, response: Response):
        # HTTP 429 (rate limiting) and 5xx (overload) make path discovery unreliable:
        # warn the user once per host instead of logging every single occurrence.
        if response.status != 429 and response.status < 500:
            return

        netloc = request.netloc
        if netloc in self.rate_limited_netlocs:
            return

        self.server_error_counts[netloc] += 1
        if self.server_error_counts[netloc] >= self.RATE_LIMIT_WARNING_THRESHOLD:
            self.rate_limited_netlocs.add(netloc)
            log_orange(
                f"[!] {netloc} is answering with HTTP 429/5xx responses (rate limiting or "
                "overload): some paths may have been missed, consider lowering the scan speed."
            )

    async def check_path(self, url, not_found_response: Response):
        request = Request(url)
        try:
            response = await self.crawler.async_send(request)
        except RequestError:
            self.network_errors += 1
            return False

        self.warn_on_rate_limiting(request, response)

        if response.redirection_url and response.is_directory_redirection:
            # A server that appends a trailing slash to every path (the improbable
            # path included) would otherwise turn every candidate into a fake directory.
            if not_found_response.is_directory_redirection:
                return False
            loc = response.redirection_url
            log_red(f"Found webpage {loc}")
            self.new_resources.append(loc)
            await self.add_info(
                finding_class=BusterFinding,
                request=request,
                info=f"Found webpage {loc} on {url}",
            )
        elif not is_false_positive(response, not_found_response) and (
            (response.redirection_url and not response.is_directory_redirection)
            # A 5xx means the server failed to answer (often it is rate-limiting the
            # scan), not that the resource exists: never report those.
            or (response.status not in [403, 404, 429] and response.status < 500)
        ):
            log_red(f"Found webpage {request.path}")
            self.new_resources.append(request.path)
            await self.add_info(
                finding_class=BusterFinding,
                request=request,
                info=f"Found webpage {request.path} on {url}",
            )
            return True

        return False

    async def test_directory(self, path: str):
        log_verbose(f"[¨] Testing directory {path}")

        # Request an improbable resource to learn how the server answers to non-existent
        # paths in this directory. The wordlist candidates have no extension, so the probe
        # must be extension-less too, otherwise application routing (soft 404, catch-all
        # redirection) is missed and every candidate ends up being a false positive.
        not_found_request = Request(path + random_string())
        try:
            not_found_response = await self.crawler.async_send(not_found_request)
        except RequestError:
            self.network_errors += 1
            return

        tasks = set()
        pending_count = 0

        with open(path_join(self.DATA_DIR, self.PATHS_FILE), encoding="utf-8", errors="ignore") as wordlist:
            while True:

                if pending_count < self.options["tasks"]:
                    try:
                        candidate = next(wordlist).strip()
                    except StopIteration:
                        pass
                    else:
                        url = path + candidate
                        if url not in self.known_dirs and url not in self.known_pages and url not in self.new_resources:
                            task = asyncio.create_task(self.check_path(url, not_found_response))
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
                    try:
                        await task
                    except RequestError:
                        self.network_errors += 1
                    tasks.remove(task)

    async def attack(self, request: Request, response: Optional[Response] = None):
        self.finished = True
        if not self.do_get:
            return

        # First we make a list of unique webdirs and webpages without parameters
        async for scanned_request, __ in self.persister.get_links(attack_module=self.name):
            path = scanned_request.path
            if path.endswith("/"):
                if path not in self.known_dirs:
                    self.known_dirs.append(path)
            else:
                if path not in self.known_pages:
                    self.known_pages.append(path)

        # Then for each known webdirs we look for unknown webpages inside
        for current_dir in self.known_dirs:
            await self.test_directory(current_dir)

        # Finally, for each discovered webdirs we look for more webpages
        while self.new_resources:
            current_res = self.new_resources.pop(0)
            if current_res.endswith("/"):
                # Mark as known then explore
                self.known_dirs.append(current_res)
                await self.test_directory(current_res)
            else:
                self.known_pages.append(current_res)
