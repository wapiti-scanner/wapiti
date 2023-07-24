import logging
from asyncio import Event
from unittest.mock import AsyncMock, patch
import re

import pytest
import respx
import httpx

from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_upload import ModuleUpload


logging.basicConfig(level=logging.DEBUG)


def upload_callback(request: httpx.Request):
    match = re.search(r"filename=\"(\w+\.\w+)\"", request.content.decode(encoding="utf-8", errors="ignore"))
    if match and match.group(1).endswith(".phtml"):
        return httpx.Response(
            200,
            text=(
                "<a href='/welcome.html'>Welcome stranger</a><br />"
                "<a href='/logout'>Logout</a><br />"
                "Access your file <a href='http://perdu.com/upl/yolo.phtml'>here</a>"
            ),
            headers={"content-type": "text/html"},
        )
    return httpx.Response(200, text="yolo")


@pytest.mark.asyncio
@respx.mock
async def test_extension_blacklist():
    with patch("wapitiCore.attack.mod_upload.random_string") as mocked_random_string:
        # Mock random_string() so we control the content of the PHP payload
        mocked_random_string.return_value = "andnowforsomethingcompletelydifferent"

        # URL with the form (not really useful, but illustrate the case)
        respx.get("http://perdu.com/").mock(
            return_value=httpx.Response(
                200,
                text=(
                    "<html><body>"
                    "<form action='upload.php' method='post' enctype='multipart/form-data'>"
                    "<input type='file' name='fileToUpload'>"
                    "<input type='submit' value='Upload Image' name='Submit'>"
                    "</form>"
                ),
                headers={"content-type": "text/html"},
            )
        )

        # URL that will be attacked
        respx.post("http://perdu.com/upload.php").mock(side_effect=upload_callback)

        # That URL will be fetched in an attempt to find the uploaded file
        respx.get("http://perdu.com/welcome.html").mock(
            return_value=
            httpx.Response(
                200,
                text="Hello there",
            )
        )

        # URL where our file was uploaded
        respx.get("http://perdu.com/upl/yolo.phtml").mock(
            return_value=
            httpx.Response(
                200,
                text="andnowforsomethingcompletelydifferent",
            )
        )

        persister = AsyncMock()
        request = Request(
            "http://perdu.com/upload.php",
            file_params=[
                ["fileToUpload", ("bar.xml", b"<xml>test</xml>", "application/xml")],
            ]
        )
        request.path_id = 42
        crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:65084/"))
        async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
            # Also make sure we respect the exclusion list
            options = {"timeout": 10, "level": 2, "excluded_urls": ["http://*logout*"]}

            module = ModuleUpload(crawler, persister, options, Event(), crawler_configuration)
            await module.attack(request)

        assert persister.add_payload.call_count
        # Make sure vulnerability was found
        assert persister.add_payload.call_args_list[0][1]["parameter"] == "fileToUpload"
        assert persister.add_payload.call_args_list[0][1]["request"].url == "http://perdu.com/upload.php"
        # Make sure we respected the exclusion list (but otherwise respx would have warned about not mocked request)
        assert any(["logout" in str(call.request.url) for call in respx.calls]) is False
