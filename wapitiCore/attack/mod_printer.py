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
from typing import Optional
from urllib.parse import urljoin
import xml.etree.ElementTree as ET

from bs4 import BeautifulSoup
from httpx import RequestError

from wapitiCore.attack.attack import Attack
from wapitiCore.definitions.fingerprint import SoftwareNameDisclosureFinding
from wapitiCore.main.log import log_blue, logging
from wapitiCore.net import Request, Response


MSG_PRINTER_VERSIONED = "{0} {1} detected"
MSG_NO_PRINTER = "No Printer Detected"
MSG_NO_FIRMWARE = ""  ##@ consider using "No Firmware Detected"
PRINTER_ENDPOINTS = {
    "hp": ["/", "/hp/device/info_deviceStatus.html", "/hp/device/this.LCDispatcher",
           "/hp/device/webAccess/index.html", "/ipp"],
    "epson": ["/", "/PRESENTATION/HTML/TOP/PRTINFO.HTML", "/webconfig",
              "/PRESENTATION/ADVANCED/HTML/PRTINFO.HTML", "/ipp", "/printer"],
    "canon": ["/", "/RemoteUI/", "/status.html", "/DeviceInformation.xml"]
}
PRINTER_BRANDS = PRINTER_ENDPOINTS.keys()


class ModulePrinter(Attack):
    """Detect Printers."""
    name = "printer"

    firmware_version = ""

    async def check_printer(self, url: str, brand: str):
        """Checks if the given URL corresponds to an HP or Epson printer."""
        brand = brand.casefold()

        if brand not in PRINTER_ENDPOINTS:
            return None

        for endpoint in PRINTER_ENDPOINTS[brand]:
            full_url = urljoin(url, endpoint)
            request = Request(full_url, 'GET')
            try:
                response: Response = await self.crawler.async_send(request, follow_redirects=False)
            except RequestError:
                self.network_errors += 1
                continue

            if not response.is_success:
                continue

                # Canon-specific HTML tag match
            if brand == "canon":
                # 1. <span id="deviceName">...</span>
                match = re.search(r'<span\s+id=["\']deviceName["\']>([^<]+)</span>', response.content)
                if match:
                    model = match.group(1).strip()
                    return f"Canon {model}"

                # Check HTTP headers for model info
            server_header = response.headers.get("Server", "")
            if brand in server_header.casefold():
                return server_header

            # Check for model info in HTML
            match = re.search(fr"({brand}\s+\w+[\w\s-]+)", response.content, re.IGNORECASE)
            if match:
                model_name = match.group(1)
                return model_name

        return None

    async def get_firmware_version(self, printer_url: str, brand: str):
        """
        Dispatcher method that routes to the correct parser based on printer brand.
        """
        match brand:
            case "epson":
                firmware = await self._get_firmware_version_epson(printer_url)
            case "hp":
                firmware = await self._get_firmware_version_hp(printer_url)
            case _:
                firmware = MSG_NO_FIRMWARE
        return firmware

    async def _get_firmware_version_epson(self, printer_url: str):
        endpoint_url = urljoin(printer_url, "/PRESENTATION/HTML/TOP/INDEX.html")
        request = Request(endpoint_url, 'GET')

        try:
            response: Response = await self.crawler.async_send(request, follow_redirects=False)
        except RequestError as req_error:
            self.network_errors += 1
            logging.error("Request Error occurred (Epson): %s", req_error)
            return MSG_NO_FIRMWARE

        soup = BeautifulSoup(response.content, 'html.parser')
        patterns = [
            r'Current\s*Version[:\s]*([A-Za-z0-9.\-]+)',
            r'Version\s*actuelle[:\s]*([A-Za-z0-9.\-]+)'
        ]

        for p in soup.find_all('p'):
            text = p.get_text(separator=' ', strip=True)
            for pattern in patterns:
                match = re.search(pattern, text, re.IGNORECASE)
                if match:
                    return match.group(1)

        return MSG_NO_FIRMWARE

    async def _get_firmware_version_hp(self, printer_url: str):
        endpoint_url = urljoin(printer_url, "/DevMgmt/ProductConfigDyn.xml")
        request = Request(endpoint_url, 'GET')

        try:
            response: Response = await self.crawler.async_send(request, follow_redirects=False)
        except RequestError as req_error:
            self.network_errors += 1
            logging.error("Request Error occurred (HP): %s", req_error)
            return MSG_NO_FIRMWARE

        if not response.is_success:
            return MSG_NO_FIRMWARE

        try:
            xml_content = response.content
            ns = {
                'dd': 'http://www.hp.com/schemas/imaging/con/dictionaries/1.0/',
                'prdcfgdyn': 'http://www.hp.com/schemas/imaging/con/ledm/productconfigdyn/2007/11/05',
            }
            root = ET.fromstring(xml_content)
            revision = root.find('.//prdcfgdyn:ProductInformation/dd:Version/dd:Revision', ns)

            if revision.text:
                return revision.text.strip()
        except ET.ParseError:
            logging.error("Failed to parse XML (HP).")

        return MSG_NO_FIRMWARE


    async def attack(self, request: Request, response: Optional[Response] = None):
        self.finished = True

        for brand in PRINTER_BRANDS:
            try:
                printer_info = await self.check_printer(request.url, brand)
                if printer_info:
                    self.firmware_version = await self.get_firmware_version(request.url, brand)
                    printer_detected = {
                        "name": printer_info,
                        "versions": [self.firmware_version],
                        "categories": ["Network Equipment"],
                        "groups": ["Printers"]
                    }

                    log_blue(MSG_PRINTER_VERSIONED, f"{printer_info}", [self.firmware_version])
                    await self.add_info(
                        finding_class=SoftwareNameDisclosureFinding,
                        request=request,
                        info=json.dumps(printer_detected),
                    )
                    return  # Stop searching if a printer is found
            except RequestError as req_error:
                self.network_errors += 1
                logging.error("Request Error occurred: %s", req_error)

        log_blue(MSG_NO_PRINTER)
