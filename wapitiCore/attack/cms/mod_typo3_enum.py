#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2023-2025 Cyberwatch
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
import json
import re
import os
from typing import Optional, List, Set, Dict

from urllib.parse import urljoin
from bs4 import BeautifulSoup
from httpx import RequestError
from arsenic import get_session, browsers, services

from wapitiCore.net import Request
from wapitiCore.attack.cms.cms_common import CommonCMS, MSG_TECHNO_VERSIONED
from wapitiCore.net.response import Response
from wapitiCore.definitions.fingerprint_webapp import SoftwareVersionDisclosureFinding
from wapitiCore.definitions.fingerprint import SoftwareNameDisclosureFinding
from wapitiCore.main.log import log_blue

MSG_NO_TYPO3 = "No TYPO3 Detected"


async def get_common_versions(json_data: Dict, list_hashes: List[str]) -> list[str]:
    """
    Given a list of hashes and a JSON file, this function returns the set of
    versions that are common across all occurrences of the provided hashes in the JSON."""

    # To store version sets for each hash found across the JSON
    hash_versions = {h: set() for h in list_hashes}
    # Iterate over each file path in the JSON data.
    for file_path, hashes in json_data.items():
        # hashes is a dict mapping a hash to a list of versions.
        for h in list_hashes:
            if h in hashes:
                hash_versions[h].update(hashes[h])

    # If any hash did not appear in the JSON, its version set remains empty.
    # In that case, we should remove all the empty entries from the list.

    hash_versions = {key: versions for key, versions in hash_versions.items() if len(versions) > 0}

    # Compute the intersection across all version sets.
    common_versions = set.intersection(*hash_versions.values()) if hash_versions else []
    return list(common_versions)


async def fetch_source_files(url):
    my_files_list = set()
    url =  urljoin(url, "typo3/")
    browser = browsers.Firefox(**{
        'moz:firefoxOptions': {
            'args': ['-headless', '-log', 'error', '-devtools']
        }
    })

    try:
        # Initialize a headless browser session to extract source files
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
        print(f"An error occurred while fetching JS files: {e}")

    return my_files_list


class ModuleTYPO3Enum(CommonCMS):
    """Detect TYPO3 version."""
    PAYLOADS_HASH = "typo3_hash_files.json"
    PAYLOADS_FILE_EXTENSIONS = "typo3_extensions.txt"
    versions = []
    extensions_list = []

    async def check_typo3_extensions(self, url, extensions_file):
        """
        Check if specific TYPO3 extensions are installed on the given URL.
        """
        installed_extensions = []

        # Create a check request with a known non-existent extension
        no_ext_url = urljoin(url, "typo3conf/ext/non_existing_ext/")
        no_ext_request = Request(f'{no_ext_url}', 'GET')

        try:
            no_ext_response: Response = await self.crawler.async_send(no_ext_request, follow_redirects=True)
            if no_ext_response.status == 403:
                # If the no_ext_response returns 403, assume all folder requests return 403
                return []
        except RequestError:
            self.network_errors += 1
            return []

        try :
            with open(
            os.path.join(self.DATA_DIR, self.PAYLOADS_FILE_EXTENSIONS),
            errors = "ignore",
            encoding = 'utf-8') as ext_list:
                for extension in ext_list:
                    extension = extension.strip()
                    ext_url = urljoin(url, f"typo3conf/ext/{extension}/")
                    request = Request(f'{ext_url}', 'GET')
                    try:
                        response: Response = await self.crawler.async_send(request, follow_redirects=True)
                    except RequestError:
                        self.network_errors += 1
                        continue

                    if response.status == 403:
                        installed_extensions.append(extension)

        except FileNotFoundError:
            print(f"Error: File '{extensions_file}' not found.")
            return []

        return installed_extensions

    async def check_typo3(self, url):

        request = Request(f'{url}', 'GET')
        try:
            response: Response = await self.crawler.async_send(request, follow_redirects=True)
        except RequestError:
            self.network_errors += 1
        else:
            soup = BeautifulSoup(response.content, 'html.parser')

            # Check meta tag for generator
            meta_generator = soup.find('meta', attrs={'name': 'generator'})
            if meta_generator and re.search(r'TYPO3\s+(?:CMS\s+)?(?:[\d.]+)?(?:\s+CMS)?',
                                            meta_generator.get('content', ''), re.I):
                return True

            # Check for TYPO3-specific links and images
            typo3_patterns = ['typo3conf', 'typo3temp']
            for tag in soup.find_all(['link', 'img']):
                for attr in ['href', 'src']:
                    if tag.has_attr(attr) and any(pattern in tag[attr] for pattern in typo3_patterns):
                        return True

            # Check script sources
            for script in soup.find_all('script', src=True):
                if re.search(r'^/?typo3(?:conf|temp)/', script['src']):
                    return True

            # Check for a known TYPO3 image probe
            typo3_probe_url = url.rstrip('/') + "/typo3/sysext/core/Resources/Public/Images/typo3_orange.svg"
            request_typo3 = Request(f'{typo3_probe_url}', 'GET')
            probe_response : Response = await self.crawler.async_send(request_typo3, follow_redirects=False)
            if probe_response.status == 200:
                return True
        return False


    async def attack(self, request: Request, response: Optional[Response] = None):
        self.finished = True
        request_to_root = Request(request.url)

        if await self.check_typo3(request_to_root.url):
            await self.detect_version(self.PAYLOADS_HASH, request_to_root.url)
            self.versions = sorted(self.versions, key=lambda x: x.split('.')) if self.versions else []

            self.extensions_list = await self.check_typo3_extensions(request_to_root.url, self.PAYLOADS_FILE_EXTENSIONS)

            if not self.versions:
                list_hashes = []
                list_paths = await fetch_source_files(request.url)
                for path in list_paths:
                    hash_val, path = await self.get_url_hash(request.url, path)
                    list_hashes.append(hash_val)
                data_hash = self.get_hashes(self.PAYLOADS_HASH)
                self.versions = await get_common_versions(data_hash, list_hashes)

            typo3_detected = {
                "name": "TYPO3",
                "versions": self.versions if self.versions else [],
                "categories": ["CMS TYPO3"],
                "groups": ["Content"]
            }

            log_blue(
                MSG_TECHNO_VERSIONED,
                "TYPO3",
                self.versions
            )

            if self.versions:
                await self.add_info(
                    finding_class=SoftwareVersionDisclosureFinding,
                    request=request_to_root,
                    info=json.dumps(typo3_detected),
                )
            await self.add_info(
                finding_class=SoftwareNameDisclosureFinding,
                request=request_to_root,
                info=json.dumps(typo3_detected),
            )
            if self.extensions_list:
                for ext in self.extensions_list:
                    extension_detected = {
                        "name": ext,
                        "versions": [],
                        "categories": ["TYPO3 extension"],
                        "groups": ['Add-ons']
                    }
                    log_blue(
                        MSG_TECHNO_VERSIONED,
                        ext,
                        []
                    )
                    await self.add_info(
                        finding_class=SoftwareNameDisclosureFinding,
                        request=request,
                        info=json.dumps(extension_detected),
                        response=response
                    )
        else:
            log_blue(MSG_NO_TYPO3)
