import asyncio
import json
import hashlib
import logging
from os.path import join as path_join
from typing import Tuple

from httpx import RequestError

from wapitiCore.net.web import Request
from wapitiCore.attack.attack import Attack
from wapitiCore.language.vulnerability import _
from wapitiCore.definitions.fingerprint import NAME as TECHNO_DETECTED
from wapitiCore.main.log import log_blue

MSG_TECHNO_VERSIONED = _("{0} {1} detected")
MSG_NO_DRUPAL = _("No Drupal Detected")


class ModuleDrupalEnum(Attack):
    """Detect Drupal version."""
    name = "drupal_enum"
    PAYLOADS_HASH = "drupal_hash_files.json"
    PAYLOADS_FILE_THEMES = "wordpress_themes.txt"

    versions = []

    def get_hashes(self):
        with open(path_join(self.DATA_DIR, self.PAYLOADS_HASH), errors="ignore", encoding='utf-8') as hashes:
            data = json.load(hashes)
            return data

    async def get_url_hash(self, root_url: str, path: str) -> Tuple[str, str]:
        request = Request(f"{root_url}{path}")
        response = await self.crawler.async_get(request)
        if response.status != 200:
            return "", ""

        return hashlib.sha256(response.content.encode()).hexdigest(), path

    async def detect_version(self, root_url):
        versions = {}
        detection_db = self.get_hashes()
        tasks = set()

        for path in detection_db:
            task = asyncio.create_task(self.get_url_hash(root_url, path))
            tasks.add(task)

            while True:
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

        # We reached the end of your list but we may still have some running tasks
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

    async def check_drupal(self, url):
        check_list = ['sites/', 'core/misc/drupal.js', 'misc/drupal.js', 'misc/test/error/404/ispresent.html']
        for item in check_list:
            request = Request(f'{url}{item}')
            try:
                response = await self.crawler.async_get(request)
            except RequestError:
                self.network_errors += 1
            except Exception as exception:
                logging.exception(exception)
            else:
                if response.status != 404:
                    return True
        return False

    async def must_attack(self, request: Request):
        if self.finished:
            return False

        if request.method == "POST":
            return False

        return request.url == await self.persister.get_root_url()

    async def attack(self, request: Request):
        self.finished = True
        request_to_root = Request(request.url)

        if await self.check_drupal(request_to_root.url):
            await self.detect_version(request_to_root.url)
            self.versions = sorted(self.versions, key=lambda x: x.split('.')) if self.versions else [""]
            drupal_detected = {
                "name": "Drupal",
                "versions": self.versions,
                "categories": ["CMS Drupal"]
            }
            log_blue(
                MSG_TECHNO_VERSIONED,
                "Drupal",
                self.versions
            )
            await self.add_addition(
                category=TECHNO_DETECTED,
                request=request_to_root,
                info=json.dumps(drupal_detected),
            )
        else:
            log_blue(MSG_NO_DRUPAL)
