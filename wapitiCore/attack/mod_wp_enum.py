import json
import re
import xml
import xml.etree.ElementTree as ET
from os.path import join as path_join
from typing import Match

from wapitiCore.attack.attack import Attack
from wapitiCore.definitions.fingerprint import NAME as TECHNO_DETECTED
from wapitiCore.definitions.fingerprint import WSTG_CODE as TECHNO_DETECTED_WSTG_CODE
from wapitiCore.definitions.fingerprint_webapp import NAME as WEB_APP_VERSIONED
from wapitiCore.language.vulnerability import _
from wapitiCore.main.log import log_blue, logging
from wapitiCore.net.page import Page
from wapitiCore.net.web import Request

MSG_TECHNO_VERSIONED = _("{0} {1} detected")
MSG_NO_WP = _("No WordPress Detected")
MSG_WP_VERSION = _("WordPress Version : {0}")


class ModuleWpEnum(Attack):
    """Detect WordPress Plugins with version."""
    name = "wp_enum"
    PAYLOADS_FILE_PLUGINS = "wordpress_plugins.txt"
    PAYLOADS_FILE_THEMES = "wordpress_themes.txt"

    def get_plugin(self):
        with open(
            path_join(self.DATA_DIR, self.PAYLOADS_FILE_PLUGINS),
            errors="ignore",
            encoding='utf-8'
        ) as plugin_list:
            for line in plugin_list:
                plugin = line.strip()
                if plugin:
                    yield plugin

    def get_theme(self):
        with open(
            path_join(self.DATA_DIR, self.PAYLOADS_FILE_THEMES),
            errors="ignore",
            encoding='utf-8'
        ) as theme_list:
            for line in theme_list:
                theme = line.strip()
                if theme:
                    yield theme

    async def detect_version(self, url: str):
        rss_urls = ["feed/", "comments/feed/", "feed/rss/", "feed/rss2/"]
        detected_version = None

        for rss_url in rss_urls:
            req = Request(f"{url}{'' if url.endswith('/') else '/'}{rss_url}")
            rep: Page = await self.crawler.async_get(req, follow_redirects=True)

            if not rep.content or rep.is_error:
                continue
            root = ET.fromstring(rep.content)

            if root is None:
                continue
            try:
                generator_text = root.findtext('./channel/generator')
            except xml.etree.ElementTree.ParseError:
                continue
            version: Match = re.search(r"\Ahttps?:\/\/wordpress\.(?:[a-z]+)\/\?v=(.*)\Z", generator_text)
            if version is None:
                continue
            detected_version = version.group(1)
            break
        if detected_version is None:
            log_blue(
                MSG_WP_VERSION,
                "N/A"
            )
        else:
            log_blue(
                MSG_WP_VERSION,
                detected_version
            )
            await self.add_vuln_info(
                category=WEB_APP_VERSIONED,
                request=req,
                info=json.dumps({"name": "WordPress", "versions": [detected_version], "categories": ["CMS", "Blogs"]})
            )

    async def detect_plugin(self, url):
        for plugin in self.get_plugin():
            if self._stop_event.is_set():
                break

            req = Request(f'{url}/wp-content/plugins/{plugin}/readme.txt')
            rep = await self.crawler.async_get(req)

            if rep.is_success:
                version = re.search(r'tag:\s*([\d.]+)', rep.content)

                # This check was added to detect invalid format of "Readme.txt" who can cause a crashe
                if version:
                    version = version.group(1)
                else:
                    logging.warning("Readme.txt is not in a valid format")
                    version = ""

                plugin_detected = {
                    "name": plugin,
                    "versions": [version],
                    "categories": ["WordPress plugins"]
                }

                log_blue(
                    MSG_TECHNO_VERSIONED,
                    plugin,
                    version
                )

                await self.add_addition(
                    category=TECHNO_DETECTED,
                    request=req,
                    info=json.dumps(plugin_detected),
                    wstg=TECHNO_DETECTED_WSTG_CODE
                )
            elif rep.status == 403:
                plugin_detected = {
                    "name": plugin,
                    "versions": [""],
                    "categories": ["WordPress plugins"]
                }
                log_blue(
                    MSG_TECHNO_VERSIONED,
                    plugin,
                    [""]
                )
                await self.add_addition(
                    category=TECHNO_DETECTED,
                    request=req,
                    info=json.dumps(plugin_detected),
                    wstg=TECHNO_DETECTED_WSTG_CODE
                )

    async def detect_theme(self, url):
        for theme in self.get_theme():
            if self._stop_event.is_set():
                break

            req = Request(f'{url}/wp-content/themes/{theme}/readme.txt')
            rep = await self.crawler.async_get(req)
            if rep.is_success:
                version = re.search(r'tag:\s*([\d.]+)', rep.content)
                # This check was added to detect invalid format of "Readme.txt" who can cause a crashe
                if version:
                    version = version.group(1)
                else:
                    version = ""
                theme_detected = {
                    "name": theme,
                    "versions": [version],
                    "categories": ["WordPress themes"]
                }
                log_blue(
                    MSG_TECHNO_VERSIONED,
                    theme,
                    version
                )
                await self.add_addition(
                    category=TECHNO_DETECTED,
                    request=req,
                    info=json.dumps(theme_detected),
                    wstg=TECHNO_DETECTED_WSTG_CODE
                )
            elif rep.status == 403:
                theme_detected = {
                    "name": theme,
                    "versions": [""],
                    "categories": ["WordPress themes"]
                }
                log_blue(
                    MSG_TECHNO_VERSIONED,
                    theme,
                    [""]
                )
                await self.add_addition(
                    category=TECHNO_DETECTED,
                    request=req,
                    info=json.dumps(theme_detected),
                    wstg=TECHNO_DETECTED_WSTG_CODE
                )

    @staticmethod
    def check_wordpress(response: object):
        if re.findall('WordPress.*', response.content):
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

        response = await self.crawler.async_send(request_to_root, follow_redirects=True)
        if self.check_wordpress(response):
            await self.detect_version(request_to_root.url)
            log_blue("----")
            log_blue(_("Enumeration of WordPress Plugins :"))
            await self.detect_plugin(request_to_root.url)
            log_blue("----")
            log_blue(_("Enumeration of WordPress Themes :"))
            await self.detect_theme(request_to_root.url)
        else:
            log_blue(MSG_NO_WP)
