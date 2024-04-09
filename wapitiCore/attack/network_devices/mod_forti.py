import json
import re
from typing import Optional
from urllib.parse import urljoin

from bs4 import BeautifulSoup
from httpx import RequestError

from wapitiCore.attack.network_devices.network_device_common import NetworkDeviceCommon, MSG_TECHNO_VERSIONED
from wapitiCore.net import Request
from wapitiCore.net.response import Response
from wapitiCore.definitions.fingerprint import NAME as TECHNO_DETECTED, WSTG_CODE
from wapitiCore.main.log import log_blue, logging

MSG_NO_FORTI = "No Forti Product Detected"


class ModuleForti(NetworkDeviceCommon):
    """Detect Forti."""
    device_name = "Fortinet"
    version = ""
    fortinet_pattern = re.compile(r'Forti\w+')

    async def check_forti(self, url):
        fortivpn_list = ['remote/fgt_lang?lang=en',
                         'remote/fgt_lang?lang=fr']
        check_list = fortivpn_list + ['logindisclaimer',
                                      'remote/login?lang=en',
                                      'remote/login?lang=fr',
                                      'fpc/app/login',
                                      'login/?next=/']

        for item in check_list:
            full_url = urljoin(url, item)
            request = Request(full_url, 'GET')
            try:
                response: Response = await self.crawler.async_send(request, follow_redirects=False)
            except RequestError:
                self.network_errors += 1
                continue

            if response.is_success:
                if item in fortivpn_list:
                    self.device_name = "Fortinet SSL-VPN"
                await self.detect_forti_product(full_url)
                return True

        # Check Fortinet product from title
        request = Request(url, 'GET')
        try:
            response: Response = await self.crawler.async_send(request, follow_redirects=False)
        except RequestError:
            self.network_errors += 1
            raise
        if response.is_success:
            soup = BeautifulSoup(response.content, 'html.parser')
            # Get the title of the webpage
            title_tag = soup.title
            if title_tag:
                title = title_tag.string
                # Check if the title contains a name starting with "Forti" (case-sensitive)
                if title and "Forti" in title:
                    self.device_name = title
                    return True

        # Check FortiMail
        url_fortimail = urljoin(url, "admin/")
        request = Request(url_fortimail, 'GET')
        try:
            response: Response = await self.crawler.async_send(request, follow_redirects=False)
        except RequestError:
            self.network_errors += 1
            raise
        if response.is_success:
            soup = BeautifulSoup(response.content, 'html.parser')
            for tag in soup.find_all(True):
                if tag.string:
                    match = self.fortinet_pattern.search(tag.text)
                    if match:
                        # Extract the matched product name
                        self.device_name = match.group()
                        return True

        # Check FortiManager
        url_fortimanager = urljoin(url, "p/login/")
        request = Request(url_fortimanager, 'GET')
        try:
            response: Response = await self.crawler.async_send(request, follow_redirects=False)
        except RequestError:
            self.network_errors += 1
            raise
        if response.is_success:
            soup = BeautifulSoup(response.content, 'html.parser')
            sign_in_header_div = soup.find('div', class_='sign-in-header')
            if sign_in_header_div and 'FortiManager' in sign_in_header_div.text:
                self.device_name = "FortiManager"
                return True

        return False

    async def detect_forti_product(self, url):
        request = Request(url, 'GET')
        try:
            # Send an HTTP GET request to the URL
            response: Response = await self.crawler.async_send(request, follow_redirects=True)
        except RequestError:
            self.network_errors += 1
            raise
        soup = BeautifulSoup(response.content, 'html.parser')

        # Get the title of the webpage
        title_tag = soup.title
        if title_tag:
            title = title_tag.string

            # Search for the pattern in the title
            match = self.fortinet_pattern.search(title)

            if match:
                # Extract the matched product name
                self.device_name = match.group()

    async def attack(self, request: Request, response: Optional[Response] = None):
        self.finished = True
        request_to_root = Request(request.url)

        try:
            if await self.check_forti(request_to_root.url):

                forti_detected = {
                    "name": self.device_name,
                    "versions": [],
                    "categories": ["Network Equipment"],
                    "groups": ["Content"]
                }
                log_blue(
                    MSG_TECHNO_VERSIONED,
                    self.device_name,
                    self.version
                )

                await self.add_addition(
                    category=TECHNO_DETECTED,
                    request=request_to_root,
                    info=json.dumps(forti_detected),
                    wstg=WSTG_CODE
                )
            else:
                log_blue(MSG_NO_FORTI)
        except RequestError as req_error:
            self.network_errors += 1
            logging.error(f"Request Error occurred: {req_error}")
