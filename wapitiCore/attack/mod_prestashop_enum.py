import json
from typing import Optional
from bs4 import BeautifulSoup
from httpx import RequestError

from wapitiCore.net import Request
from wapitiCore.attack.mod_cms import ModuleCms, MSG_TECHNO_VERSIONED
from wapitiCore.net.response import Response
from wapitiCore.definitions.fingerprint_webapp import NAME as WEB_APP_VERSIONED, WSTG_CODE as WEB_WSTG_CODE
from wapitiCore.definitions.fingerprint import NAME as TECHNO_DETECTED, WSTG_CODE
from wapitiCore.main.log import log_blue

MSG_NO_PRESTASHOP = "No PrestaShop Detected"


class ModulePrestashopEnum(ModuleCms):
    """Detect PrestaShop version."""
    name = "prestashop_enum"
    PAYLOADS_HASH = "prestashop_hash_files.json"

    versions = []

    async def check_prestashop(self, url):

        request = Request(f'{url}', 'GET')
        try:
            response: Response = await self.crawler.async_send(request, follow_redirects=True)
        except RequestError:
            self.network_errors += 1
        else:
            soup = BeautifulSoup(response.content, 'html.parser')

            # Look for common PrestaShop elements or text
            common_prestashop_elements = [
                "PrestaShop",  # Look for the presence of the text "PrestaShop"
                "prestashop.min.css",  # Check for the CSS file often used by PrestaShop
                "PrestaShop.modules",  # Check for JavaScript code often used by PrestaShop
                "Powered by <a href='https://www.prestashop.com'",  # Detects "Powered by PrestaShop" text
                "prestashop-bootstrap.min.css",  # Check for another common CSS file
                "prestashop.js",
                "/revsliderprestashop/",
                "prestashop-widget",
                "for_prestashop",
                "themes/.*/assets",
                "prestashop ="
                # Check for another common JavaScript file
            ]
            # Check for the presence of any common PrestaShop elements or text
            for element in common_prestashop_elements:
                if element in str(soup):
                    return True

        return False

    async def must_attack(self, request: Request, response: Optional[Response] = None):
        if self.finished:
            return False

        if request.method == "POST":
            return False

        return request.url == await self.persister.get_root_url()

    async def attack(self, request: Request, response: Optional[Response] = None):
        self.finished = True
        request_to_root = Request(request.url)

        if await self.check_prestashop(request_to_root.url):
            await self.detect_version(self.PAYLOADS_HASH, request_to_root.url)
            self.versions = sorted(self.versions, key=lambda x: x.split('.')) if self.versions else []

            prestashop_detected = {
                "name": "PrestaShop",
                "versions": self.versions,
                "categories": ["CMS PrestaShop"],
                "groups": ["Content"]
            }

            log_blue(
                MSG_TECHNO_VERSIONED,
                "PrestaShop",
                self.versions
            )

            if self.versions:
                await self.add_vuln_info(
                    category=WEB_APP_VERSIONED,
                    request=request_to_root,
                    info=json.dumps(prestashop_detected),
                    wstg=WEB_WSTG_CODE
                )
            await self.add_addition(
                category=TECHNO_DETECTED,
                request=request_to_root,
                info=json.dumps(prestashop_detected),
                wstg=WSTG_CODE
            )
        else:
            log_blue(MSG_NO_PRESTASHOP)
