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
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import urlparse, urlunparse, urlencode
from typing import Dict, Any
from uuid import uuid4

from wapiti_swagger.models import Parameter
from wapiti_swagger.parser import parse, generate_request_body_from_schema

from wapitiCore.net import Request
from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net.crawler import AsyncCrawler

default_string_values = {
    "date": "2024-01-01",
    "date-time": "2023-03-03T20:35:34.32",
    "email": "wapiti2021@mailinator.com",
    "uuid": str(uuid4()),
    "hostname": "google.com",
    "ipv4": "8.8.8.8",
    "ipv6": "2a00:1450:4007:818::200e",
    "uri": "https://wapiti-scanner.github.io/",
    "url": "https://wapiti-scanner.github.io/",
    "byte": "d2FwaXRp",
    "binary": "hello there",
    "password": "Letm3in_"
}


# pylint: disable=too-many-return-statements
def get_value(parameter: Parameter):
    if parameter.default is not None:
        if isinstance(parameter.default, bool):
            return str(parameter.default).lower()
        return str(parameter.default)

    if parameter.param_type == "file":
        return "pix.gif", b"GIF89a", "image/gif"
    if parameter.param_type == "integer":
        return "1"
    if parameter.param_type == "boolean":
        return "true"

    if parameter.param_type in ("string", ""):
        # check parameter allowed format first
        value = default_string_values.get(parameter.param_format)
        if value:
            return value

        if parameter.name.lower().endswith("id"):
            return "1"
        if "mail" in parameter.name.lower():
            return "wapiti2021@mailinator.com"
        if "url" in parameter.name.lower():
            return "https://wapiti-scanner.github.io/"
        if "pass" in parameter.name.lower() or "pwd" in parameter.name.lower():
            return "Letm3in_"
        if "user" in parameter.name.lower() or "log" in parameter.name.lower():
            return "alice"

        return "default"

    return "1"


def get_api_url(metadata: Dict[str, Any], base_url: str) -> str:
    path = ""
    for server in sorted(metadata.get("servers", []), reverse=True):
        if server.startswith(("http://", "https://")):
            return server

        if server.startswith("/"):
            path = server

    base_url_parts = urlparse(base_url)
    scheme = sorted(metadata["schemes"])[-1] if len(metadata.get("schemes", [])) else base_url_parts.scheme
    netloc = metadata.get("host") or base_url_parts.netloc
    path = path or metadata.get("basePath") or base_url_parts.path

    return urlunparse((scheme, netloc, path, "", "", ""))


class Swagger:
    swagger_dict = None
    routes = None


    def __init__(self, swagger_url: str, base_url: str, crawler_configuration: CrawlerConfiguration) -> None:
        self._swagger_url = swagger_url
        self._base_url = base_url
        self._crawler_configuration = crawler_configuration

    async def get_requests(self) -> list[Request]:
        if self._swagger_url.startswith(("http://", "https://")):
            async with AsyncCrawler.with_configuration(self._crawler_configuration) as crawler:
                response = await crawler.async_get(Request(self._swagger_url), follow_redirects=True)
                if not 200 <= response.status < 300:
                    raise RuntimeError(f"Got an unexpected status code for the given swagger URL: {response.status}")
                with TemporaryDirectory() as temp_dir:
                    temp_path = Path(temp_dir) / Path(urlparse(self._swagger_url).path).name
                    with temp_path.open("w") as file_obj:
                        file_obj.write(response.content)

                    parsed_swagger = parse(str(temp_path))
        else:
            swagger_path = Path(self._swagger_url)
            if not swagger_path.exists():
                raise FileNotFoundError("Could not find the given swagger file")

            parsed_swagger = parse(self._swagger_url)

        api_base_url = get_api_url(parsed_swagger.metadata, self._base_url).rstrip("/")
        results = []

        for request in parsed_swagger.requests:
            headers = {}
            get_params = []
            post_params = []
            json_body = None
            file_params = None

            final_path = request.path
            content_type = "application/json"

            for parameter in request.parameters:
                if parameter.location == "body":
                    json_body = generate_request_body_from_schema(
                        parameter.schema,
                        parsed_swagger.components
                    )
                    if parameter.media_type == "application/x-www-form-urlencoded":
                        json_body = urlencode(json_body, doseq=True)
                        content_type = "application/x-www-form-urlencoded"
                    else:
                        json_body = json.dumps(json_body)
                else:
                    value = get_value(parameter) or "1"

                    if parameter.param_type == "array":
                        value = generate_request_body_from_schema(
                            parameter.schema,
                            parsed_swagger.components
                        )

                        # we do not support list in locations different from the body
                        # let's pop the first item of the list
                        if isinstance(value, list):
                            value = value[0] if value else "default"

                    if parameter.location == "header":
                        headers[parameter.name] = value
                    elif parameter.location == "path":
                        final_path = final_path.replace(f"{{{parameter.name}}}", str(value))
                    elif parameter.location == "query":
                        get_params.append([parameter.name, value])
                    elif parameter.location == "formData":
                        content_type = "application/x-www-form-urlencoded"
                        if parameter.param_type == "file":
                            file_params = file_params or []
                            file_params.append([parameter.name, ("pix.gif", b"GIF89a", "image/gif")])
                        else:
                            post_params.append([parameter.name, value])

            request = Request(
                path=api_base_url + final_path,
                method=request.method,
                get_params=get_params,
                post_params=json_body or post_params,
                file_params=file_params,
                enctype="multipart/form-data" if file_params else content_type,
            )
            results.append(request)

        return results
