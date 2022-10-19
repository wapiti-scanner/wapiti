from asyncio import Event
from unittest.mock import AsyncMock

import httpx
import respx
import pytest

from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_ssrf import ModuleSsrf


@pytest.mark.asyncio
@respx.mock
async def test_whole_stuff():
    # Test attacking all kind of parameter without crashing
    respx.route(host="perdu.com").mock(return_value=httpx.Response(200, text="Hello there"))

    persister = AsyncMock()
    all_requests = []

    request = Request("http://perdu.com/")
    request.path_id = 1
    all_requests.append(request)

    request = Request("http://perdu.com/?foo=bar")
    request.path_id = 2
    all_requests.append(request)

    request = Request(
        "http://perdu.com/?foo=bar",
        post_params=[["a", "b"]],
        file_params=[["file", ("calendar.xml", b"<xml>Hello there</xml", "application/xml")]]
    )
    request.path_id = 3
    all_requests.append(request)

    def get_path_by_id(request_id):
        for req in all_requests:
            if req.path_id == int(request_id):
                return req
        return None

    persister.get_path_by_id.side_effect = get_path_by_id

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleSsrf(crawler, persister, options, Event(), crawler_configuration)
        module.do_post = True

        respx.get("https://wapiti3.ovh/get_ssrf.php?session_id=" + module._session_id).mock(
            return_value=httpx.Response(
                200,
                json={
                    "3": {
                        "66696c65": [
                            {
                                "date": "2019-08-17T16:52:41+00:00",
                                "url": "https://wapiti3.ovh/ssrf_data/yolo/3/66696c65/31337-0-192.168.2.1.txt",
                                "ip": "192.168.2.1",
                                "method": "GET"
                            }
                        ]
                    }
                }
            )
        )

        for request in all_requests:
            await module.attack(request)

        assert not persister.add_payload.call_count
        # We must trigger finish() normally called by wapiti.py
        await module.finish()

        assert persister.add_payload.call_count
        assert persister.add_payload.call_args_list[0][1]["module"] == "ssrf"
        assert persister.add_payload.call_args_list[0][1]["category"] == "Server Side Request Forgery"
        assert persister.add_payload.call_args_list[0][1]["parameter"] == "file"
        assert persister.add_payload.call_args_list[0][1]["request"].file_params == [
            ['file', ('http://external.url/page', b'<xml>Hello there</xml', 'application/xml')]
        ]
