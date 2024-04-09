import json
import re
from typing import Optional
from urllib.parse import urljoin

from httpx import RequestError

from wapitiCore.attack.network_devices.network_device_common import NetworkDeviceCommon, MSG_TECHNO_VERSIONED
from wapitiCore.net import Request
from wapitiCore.net.response import Response
from wapitiCore.definitions.fingerprint import NAME as TECHNO_DETECTED, WSTG_CODE
from wapitiCore.main.log import log_blue, logging

MSG_NO_HARBOR = "No Harbor Product Detected"


class ModuleHarbor(NetworkDeviceCommon):
    """Detect Harbor."""

    device_name = "Harbor"
    version = ""

    async def check_harbor(self, url):
        check_list = ['api/v2.0/systeminfo']

        for item in check_list:
            full_url = urljoin(url, item)
            request = Request(full_url, 'GET')
            try:
                response: Response = await self.crawler.async_send(request, follow_redirects=False)
            except RequestError:
                self.network_errors += 1
                raise

            if (response.is_success and "content-type" in response.headers
                    and "json" in response.headers["content-type"]):
                try:
                    await self.detect_harbor_version(response.content)
                except ValueError:
                    logging.error(f"Cannot extract version from {full_url}")
                return True

        return False

    async def detect_harbor_version(self, response_content):
        try:
            # Parse the JSON content
            data = json.loads(response_content)
            # Extract the harbor_version value
            if data.get("harbor_version"):
                self.version = data.get("harbor_version")
        except (json.JSONDecodeError, KeyError) as json_error:
            raise ValueError("The URL doesn't contain a valid JSON.") from json_error

    async def attack(self, request: Request, response: Optional[Response] = None):
        self.finished = True
        request_to_root = Request(request.url)

        try:
            if await self.check_harbor(request_to_root.url):
                harbor_detected = {
                    "name": self.device_name,
                    "versions": [self.version] if self.version else [],
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
                    info=json.dumps(harbor_detected),
                    wstg=WSTG_CODE
                )
            else:
                log_blue(MSG_NO_HARBOR)
        except RequestError as req_error:
            self.network_errors += 1
            logging.error(f"Request Error occurred: {req_error}")

