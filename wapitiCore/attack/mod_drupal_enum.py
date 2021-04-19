import json
import hashlib
from os.path import join as path_join

from wapitiCore.net.web import Request
from wapitiCore.attack.attack import Attack
from wapitiCore.language.vulnerability import LOW_LEVEL, _
from wapitiCore.definitions.fingerprint import NAME as TECHNO_DETECTED

MSG_TECHNO_VERSIONED = _("{0} {1} detected")
MSG_NO_DRUPAL = _("No Drupal Detected")


class mod_drupal_enum(Attack):
    """Detect Drupal version."""
    name = "drupal_enum"
    PAYLOADS_HASH = "drupal_hash_files.json"
    PAYLOADS_FILE_THEMES = "wordpress_themes.txt"

    versions = []

    def get_hash(self):
        with open(path_join(self.DATA_DIR, self.PAYLOADS_HASH), errors="ignore") as hashes:
            data = json.load(hashes)
            return data

    async def detect_version(self, url):
        vers = {}
        data = self.get_hash()
        for uri in data:
            if self._stop_event.is_set():
                break

            req = Request('{}{}'.format(url, uri))
            rep = await self.crawler.async_get(req)
            if rep.status != 200:
                continue

            cont = rep.content.encode()
            hash_content = hashlib.sha256(cont).hexdigest()

            if uri in data:
                if hash_content in data[uri]:
                    vers[uri] = data[uri][hash_content]
        if vers:
            self.versions = set.intersection(*[set(versions) for versions in vers.values()])

    async def check_drupal(self, url):
        check_list = ['sites/', 'core/misc/drupal.js', 'misc/drupal.js', 'misc/test/error/404/ispresent.html']
        for item in check_list:
            req = Request('{}{}'.format(url, item))
            rep = await self.crawler.async_get(req)
            if rep.status != 404:
                return True
        return False

    def must_attack(self, request: Request):
        if self.finished:
            return False

        if request.method == "POST":
            return False
        return request.url == self.persister.get_root_url()

    async def attack(self, request: Request):
        self.finished = True
        request_to_root = Request(request.url)

        if await self.check_drupal(request_to_root.url):
            await self.detect_version(request_to_root.url)
            if self.versions:
                self.versions = sorted(self.versions, key=lambda x: [i for i in x.split('.')])
                drupal_detected = {
                    "name": "Drupal",
                    "versions": self.versions,
                    "categories": ["CMS Drupal"]
                }
                self.log_blue(
                    MSG_TECHNO_VERSIONED,
                    "Drupal",
                    self.versions
                )
                self.add_addition(
                    category=TECHNO_DETECTED,
                    level=LOW_LEVEL,
                    request=request_to_root,
                    info=json.dumps(drupal_detected)
                )
            else:
                drupal_detected = {
                    "name": "Drupal",
                    "versions": [""],
                    "categories": ["CMS Drupal"]
                }
                self.log_blue(
                    MSG_TECHNO_VERSIONED,
                    "Drupal",
                    []
                )
                self.add_addition(
                    category=TECHNO_DETECTED,
                    level=LOW_LEVEL,
                    request=request_to_root,
                    info=json.dumps(drupal_detected)
                )
        else:
            self.log_blue(MSG_NO_DRUPAL)
