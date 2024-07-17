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
import hashlib
import json
import os
import re
from typing import Optional, Tuple
from urllib.parse import urlparse

from arsenic import get_session, browsers, services
from bs4 import BeautifulSoup
from httpx import RequestError

from wapitiCore.net import Request
from wapitiCore.attack.cms.cms_common import CommonCMS, MSG_TECHNO_VERSIONED, calculate_git_hash
from wapitiCore.net.response import Response
from wapitiCore.definitions.fingerprint_webapp import SoftwareVersionDisclosureFinding
from wapitiCore.definitions.fingerprint import SoftwareNameDisclosureFinding
from wapitiCore.main.log import log_blue

MSG_NO_MAGENTO = "No Magento Detected"


async def fetch_source_files(url):
    my_files_list = set()
    browser = browsers.Firefox(**{
        'moz:firefoxOptions': {
            'args': ['-headless', '-log', 'error', '-devtools']
        }
    })

    try:
        # Initialize a headless browser session to extract source filess
        async with get_session(services.Geckodriver(log_file=os.devnull), browser) as headless_client:
            await headless_client.get(url)
            content = await headless_client.get_page_source()  # Fetch the fully rendered page content

            soup = BeautifulSoup(content, "html.parser")

            # Collect JS and CSS file links
            js_files = {script.get('src') for script in soup.find_all('script') if script.get('src')}
            css_files = {link.get('href') for link in soup.find_all('link', rel="stylesheet") if link.get('href')}

            my_files_list.update(js_files)
            my_files_list.update(css_files)

    except Exception as e:
        print(f"An error occurred while fetching JS files and CSS files: {e}")

    return my_files_list

def get_root_url(url):
    # Parse the URL into components
    parsed_url = urlparse(url)
    # Reconstruct the root URL from the scheme and netloc
    root_url = f"{parsed_url.scheme}://{parsed_url.netloc}/"
    return root_url


class ModuleMagentoEnum(CommonCMS):
    """Detect Magento version."""
    PAYLOADS_HASH = "magento2_hash_files.json"
    versions = []
    url_list = []

    def init(self, crawler, persister, options, event, crawler_configuration):
        CommonCMS.__init__(self,
                           crawler=crawler,
                           persister=persister,
                           attack_options=options,
                           crawler_configuration=crawler_configuration)
        self.url_list = []

    async def fetch_source_list(self, url):
        self.url_list = await fetch_source_files(url)
        return True

    async def check_magento(self, url):
        """Return the list of urls or None if nothing was founded."""
        try:
            request = Request(f'{url}', 'GET')
            response: Response = await self.crawler.async_send(request, follow_redirects=True)
        except RequestError:
            self.network_errors += 1
            return None
        soup = BeautifulSoup(response.content, 'html.parser')
        pattern = re.compile(r'skin/frontend/.*/default/.*')
        script_tags = soup.find_all('script')

        keywords = [
            "magento_opensource", "x-magento-init", "Magento_Ui",
            "Magento_PageBuilder", "VarienForm", "Magento_Enterprise"
        ]

        if (response.is_success and
            (
                any(keyword in response.content for keyword in keywords) or
                "Magento" in response.headers.get('X-Powered-By', '')
            )
        ):
            return await self.fetch_source_list(url)

        for script in script_tags:
            if 'src' in script.attrs and "Magento_Theme" in script['src']:
                return await self.fetch_source_list(url)

        for link in soup.find_all('link'):
            if 'href' in link.attrs:
                src = link['href']
                if pattern.search(src):
                    return await self.fetch_source_list(url)

        for cookie in response.cookies:
            if cookie.startswith(('frontend', 'X-Magento', 'mage-')):
                return await self.fetch_source_list(url)

        return None

    async def detect_magento_version(self, payloads_hash, hashes):
        versions = {}
        detection_db = self.get_hashes(payloads_hash)
        for content_hash, path in hashes:

            if content_hash and content_hash in detection_db:
                versions[content_hash] = detection_db[content_hash]

        if versions:
            self.versions = set.intersection(*[set(versions) for versions in versions.values()])

    async def get_url_hashes(self, url: str) -> Tuple[str, str]:
        if get_root_url(url) == await self.persister.get_root_url():
            request = Request(f"{url}", "GET")
            try:
                response: Response = await self.crawler.async_send(request, follow_redirects=True)
            except RequestError:
                self.network_errors += 1
                return "",""

            file_content = response.bytes
            git_hash = calculate_git_hash(file_content)

            return git_hash, url

    async def attack(self, request: Request, response: Optional[Response] = None):
        self.finished = True
        request_to_root = Request(request.url)
        hashes = []
        if await self.check_magento(request_to_root.url):
            for url in self.url_list:
                hash_val = await self.get_url_hashes(url)
                if hash_val:
                    hashes.append(hash_val)
            await self.detect_magento_version(self.PAYLOADS_HASH, hashes)
            self.versions = sorted(self.versions, key=lambda x: x.split('.')) if self.versions else []

            magento_detected = {
                "name": "Magento",
                "versions": list(self.versions),
                "categories": ["CMS Magento"],
                "groups": ["Content"]
            }

            log_blue(
                MSG_TECHNO_VERSIONED,
                "Magento!",
                self.versions
            )

            if self.versions:
                await self.add_info(
                    finding_class=SoftwareVersionDisclosureFinding,
                    request=request_to_root,
                    info=json.dumps(magento_detected),
                )
            await self.add_info(
                finding_class=SoftwareNameDisclosureFinding,
                request=request_to_root,
                info=json.dumps(magento_detected),
            )
        else:
            log_blue(MSG_NO_MAGENTO)
