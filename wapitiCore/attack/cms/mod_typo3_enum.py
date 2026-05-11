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
from os.path import join as path_join
from typing import Optional, List, Set, Dict

from urllib.parse import urljoin
from httpx import RequestError
from asyncio import TimeoutError
from playwright.async_api import async_playwright, Page, Browser, Error as PlaywrightError

from wapitiCore.parsers.html_parser import Html
from wapitiCore.net import Request
from wapitiCore.attack.cms.cms_common import CommonCMS, MSG_TECHNO_VERSIONED
from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net.response import Response
from wapitiCore.definitions.fingerprint_webapp import SoftwareVersionDisclosureFinding
from wapitiCore.definitions.fingerprint import SoftwareNameDisclosureFinding
from wapitiCore.main.log import logging, log_blue

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


async def playwright_get_content(url: str, page: Page, browser: Browser, crawler_configuration: CrawlerConfiguration) -> str:
    html = ""
    try:
        await page.goto(
            url,
            timeout = crawler_configuration.timeout * 1000,
            wait_until="load"
        )

        html = await page.content()
        return html
    except PlaywrightError as exception:
        logging.exception(exception)
        return ""
    finally:
        await browser.close()
        


async def fetch_source_files(url: str, crawler_configuration: CrawlerConfiguration) -> set:
    my_files_list = set()
    url =  urljoin(url, "typo3/")
    proxy_settings = None
    if crawler_configuration.proxy:
        proxy_settings = {"server": crawler_configuration.proxy}

    try:
        # Initialize a headless browser session to extract source files
        async with async_playwright() as pw:
            browser = await pw.firefox.launch(
                headless=True,
                proxy=proxy_settings,
                firefox_user_prefs={
                    "network.proxy.allow_hijacking_localhost": True,
                    "devtools.jsonview.enabled": False,
                }
            )
            context = await browser.new_context(
                ignore_https_errors=True, 
                user_agent=crawler_configuration.user_agent
            )
            page = await context.new_page()

            html = await playwright_get_content(url, page, browser, crawler_configuration)
            parsed = Html(html, url)

            # Collect JS and CSS file links
            js_files = {script['src'] for script in parsed.soup.find_all('script', src=True)}
            css_files = {link['href'] for link in parsed.soup.find_all('link', rel="stylesheet", href=True)}

            my_files_list.update(js_files)
            my_files_list.update(css_files)

    except (PlaywrightError, FileNotFoundError, TimeoutError) as exception:
            # Playwright browser may be missing, etc
            logging.exception(exception)
            logging.warning(
                "Could not run headless browser. "
                "Make sure playwright is installed (`pip install playwright`) "
                "and browsers are installed (`playwright install`)."
            )

    except Exception as e:
        logging.error("An error occurred while fetching JS files: %s", e)

    return my_files_list


class ModuleTYPO3Enum(CommonCMS):
    """Detect TYPO3 version."""
    PAYLOADS_HASH = "typo3_hash_files.json"
    PAYLOADS_FILE_EXTENSIONS = "typo3_extensions.txt"
    versions = []
    extensions_list = []

    async def check_typo3_extensions(self, url):
        """
        Check if specific TYPO3 extensions are installed on the given URL.
        """
        installed_extensions = []

        no_ext_url = urljoin(url, "typo3conf/ext/non_existing_ext/")
        no_ext_request = Request(no_ext_url, 'GET')

        try:
            no_ext_response: Response = await self.crawler.async_send(no_ext_request, follow_redirects=True)
            if no_ext_response.status == 403:
                return []
        except RequestError:
            self.network_errors += 1
            return []

        extensions_path = path_join(self.DATA_DIR, self.PAYLOADS_FILE_EXTENSIONS)
        try:
            with open(extensions_path, errors="ignore", encoding="utf-8") as ext_list:
                for extension in ext_list:
                    extension = extension.strip()
                    ext_url = urljoin(url, f"typo3conf/ext/{extension}/")
                    request = Request(ext_url, 'GET')
                    try:
                        response: Response = await self.crawler.async_send(request, follow_redirects=True)
                    except RequestError:
                        self.network_errors += 1
                        continue

                    if response.status == 403:
                        installed_extensions.append(extension)

        except FileNotFoundError:
            logging.error("TYPO3 extensions file not found: %s", extensions_path)
            return []

        return installed_extensions


    async def check_typo3(self, url):

        request = Request(f'{url}', 'GET')
        try:
            response: Response = await self.crawler.async_send(request, follow_redirects=True)
        except RequestError:
            self.network_errors += 1
        else:
            page = Html(response.content, url)

            # Check meta tag for generator
            meta_generator = page.soup.find('meta', attrs={'name': 'generator'})
            if meta_generator and re.search(r'TYPO3\s+(?:CMS\s+)?(?:[\d.]+)?(?:\s+CMS)?',
                                            meta_generator.get('content', ''), re.I):
                return True

            # Check for TYPO3-specific links and images
            typo3_patterns = ['typo3conf', 'typo3temp']
            for tag in page.soup.find_all(['link', 'img']):
                for attr in ['href', 'src']:
                    if tag.has_attr(attr) and any(pattern in tag[attr] for pattern in typo3_patterns):
                        return True

            # Check script sources
            for script in page.soup.find_all('script', src=True):
                if re.search(r'^/?typo3(?:conf|temp)/', script['src']):
                    return True

            # Check for a known TYPO3 image probe
            typo3_probe_url = url.rstrip('/') + "/typo3/sysext/core/Resources/Public/Images/typo3_orange.svg"
            request_typo3 = Request(typo3_probe_url, 'GET')
            try:
                probe_response: Response = await self.crawler.async_send(request_typo3, follow_redirects=False)
            except RequestError:
                self.network_errors += 1
                return False
            if probe_response.status == 200 and "svg" in probe_response.headers.get("content-type", ""):
                return True
        return False


    async def attack(self, request: Request, response: Optional[Response] = None):
        self.finished = True
        request_to_root = Request(request.url)

        if await self.check_typo3(request_to_root.url):
            await self.detect_version(self.PAYLOADS_HASH, request_to_root.url)
            self.versions = sorted(self.versions, key=lambda x: x.split('.')) if self.versions else []

            self.extensions_list = await self.check_typo3_extensions(request_to_root.url)

            if not self.versions:
                list_hashes = []
                list_paths = await fetch_source_files(request.url, self.crawler_configuration)
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
