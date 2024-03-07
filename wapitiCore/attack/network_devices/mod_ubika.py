import json
import re
from typing import Optional
from urllib.parse import urljoin

from bs4 import BeautifulSoup
from httpx import RequestError

from wapitiCore.attack.attack import Attack
from wapitiCore.net import Request
from wapitiCore.net.response import Response
from wapitiCore.definitions.fingerprint import NAME as TECHNO_DETECTED, WSTG_CODE
from wapitiCore.main.log import log_blue, logging

MSG_TECHNO_VERSIONED = "{0} {1} detected"
MSG_NO_UBIKA = "No UBIKA Detected"


class ModuleUbika(Attack):
    """Base class for detecting version."""
    version = ""

    async def check_ubika(self, url):
        check_list = ['app/monitor/']
        for item in check_list:
            full_url = urljoin(url, item)
            request = Request(full_url, 'GET')
            try:
                response: Response = await self.crawler.async_send(request, follow_redirects=True)
            except RequestError:
                self.network_errors += 1
                raise
            soup = BeautifulSoup(response.content, 'html.parser')
            title_tag = soup.title
            return response.is_success and title_tag and "UBIKA" in title_tag.text.strip()

    async def get_ubika_version(self, url):
        version = ""
        version_uri = "app/monitor/api/info/product"
        full_url = urljoin(url, version_uri)
        request = Request(full_url, 'GET')
        try:
            response: Response = await self.crawler.async_send(request, follow_redirects=True)
        except RequestError:
            self.network_errors += 1
            raise

        if response.is_success:
            version = response.json.get("result", {}).get("product", {}).get("version", '')
        return version

    async def attack(self, request: Request, response: Optional[Response] = None):
        self.finished = True
        request_to_root = Request(request.url)

        try:
            if await self.check_ubika(request_to_root.url):
                try:
                    self.version = await self.get_ubika_version(request_to_root.url)
                except RequestError as req_error:
                    self.network_errors += 1
                    logging.error(f"Request Error occurred: {req_error}")

                ubika_detected = {
                    "name": "UBIKA WAAP",
                    "version": self.version,
                    "categories": ["Network Equipment"],
                    "groups": ["Content"]
                }
                log_blue(
                    MSG_TECHNO_VERSIONED,
                    "UBIKA WAAP",
                    self.version
                )

                await self.add_addition(
                    category=TECHNO_DETECTED,
                    request=request_to_root,
                    info=json.dumps(ubika_detected),
                    wstg=WSTG_CODE
                )
            else:
                log_blue(MSG_NO_UBIKA)
        except RequestError as req_error:
            self.network_errors += 1
            logging.error(f"Request Error occurred: {req_error}")
