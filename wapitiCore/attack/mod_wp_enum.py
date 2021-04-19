import re
import json
from os.path import join as path_join

from wapitiCore.net.web import Request
from wapitiCore.attack.attack import Attack
from wapitiCore.language.vulnerability import LOW_LEVEL, _
from wapitiCore.definitions.fingerprint import NAME as TECHNO_DETECTED

MSG_TECHNO_VERSIONED = _("{0} {1} detected")
MSG_NO_WP = _("No WordPress Detected")


class mod_wp_enum(Attack):
    """Detect WordPress Plugins with version."""
    name = "wp_enum"
    PAYLOADS_FILE_PLUGINS = "wordpress_plugins.txt"
    PAYLOADS_FILE_THEMES = "wordpress_themes.txt"

    def get_plugin(self):
        with open(path_join(self.DATA_DIR, self.PAYLOADS_FILE_PLUGINS), errors="ignore") as plugin_list:
            for line in plugin_list:
                plugin = line.strip()
                if plugin:
                    yield plugin

    def get_theme(self):
        with open(path_join(self.DATA_DIR, self.PAYLOADS_FILE_THEMES), errors="ignore") as theme_list:
            for line in theme_list:
                theme = line.strip()
                if theme:
                    yield theme

    async def detect_plugin(self, url):
        for plugin in self.get_plugin():
            if self._stop_event.is_set():
                break

            req = Request('{}/wp-content/plugins/{}/readme.txt'.format(url, plugin))
            rep = await self.crawler.async_get(req)

            if rep.status == 200:
                version = re.search(r'tag:\s*([\d.]+)', rep.content)

                # This check was added to detect invalid format of "Readme.txt" who can cause a crashe
                if version:
                    version = version.group(1)
                else:
                    print("Readme.txt is not in a valid format")
                    version = ""

                plugin_detected = {
                    "name": plugin,
                    "versions": [version],
                    "categories": ["WordPress plugins"]
                }

                self.log_blue(
                    MSG_TECHNO_VERSIONED,
                    plugin,
                    version
                )

                self.add_addition(
                    category=TECHNO_DETECTED,
                    level=LOW_LEVEL,
                    request=req,
                    info=json.dumps(plugin_detected)
                )
            elif rep.status == 403:
                plugin_detected = {
                    "name": plugin,
                    "versions": [""],
                    "categories": ["WordPress plugins"]
                }
                self.log_blue(
                    MSG_TECHNO_VERSIONED,
                    plugin,
                    [""]
                )
                self.add_addition(
                    category=TECHNO_DETECTED,
                    level=LOW_LEVEL,
                    request=req,
                    info=json.dumps(plugin_detected)
                )

    async def detect_theme(self, url):
        for theme in self.get_theme():
            if self._stop_event.is_set():
                break

            req = Request('{}/wp-content/themes/{}/readme.txt'.format(url, theme))
            rep = await self.crawler.async_get(req)
            if rep.status == 200:
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
                self.log_blue(
                    MSG_TECHNO_VERSIONED,
                    theme,
                    version
                )
                self.add_addition(
                    category=TECHNO_DETECTED,
                    level=LOW_LEVEL,
                    request=req,
                    info=json.dumps(theme_detected)
                )
            elif rep.status == 403:
                theme_detected = {
                    "name": theme,
                    "versions": [""],
                    "categories": ["WordPress themes"]
                }
                self.log_blue(
                    MSG_TECHNO_VERSIONED,
                    theme,
                    [""]
                )
                self.add_addition(
                    category=TECHNO_DETECTED,
                    level=LOW_LEVEL,
                    request=req,
                    info=json.dumps(theme_detected)
                )

    def check_wordpress(self, response: object):
        if re.findall('WordPress.*', response.content):
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

        response = await self.crawler.async_send(request_to_root, follow_redirects=True)
        if self.check_wordpress(response):
            self.log_blue(_("Enumeration of WordPress Plugins :"))
            await self.detect_plugin(request_to_root.url)
            self.log_blue("----")
            self.log_blue(_("Enumeration of WordPress Themes :"))
            await self.detect_theme(request_to_root.url)
        else:
            self.log_blue(MSG_NO_WP)
