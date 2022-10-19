from asyncio import Event
from unittest.mock import AsyncMock

import httpx
import respx
import pytest

from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net import Request, Response
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_htaccess import ModuleHtaccess


@pytest.mark.asyncio
@respx.mock
async def test_whole_stuff():
    # Test attacking all kind of parameter without crashing
    respx.get("http://perdu.com/").mock(return_value=httpx.Response(200, text="Default page"))

    respx.get("http://perdu.com/admin/").mock(return_value=httpx.Response(401, text="Private section"))

    respx.route(method="ABC", host="perdu.com", path="/admin/").mock(
        return_value=httpx.Response(200, text="Hello there")
    )

    persister = AsyncMock()
    all_requests = []

    request = Request("http://perdu.com/")
    request.path_id = 1
    response = Response(
        httpx.Response(status_code=200),
        url="http://perdu.com/"
    )
    all_requests.append((request, response))

    request = Request("http://perdu.com/admin/")
    request.path_id = 2
    response = Response(
        httpx.Response(status_code=401),
        url="http://perdu.com/admin/"
    )
    all_requests.append((request, response))

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleHtaccess(crawler, persister, options, Event(), crawler_configuration)
        module.do_get = True
        for request, response in all_requests:
            if await module.must_attack(request, response):
                await module.attack(request, response)
            else:
                assert request.path_id == 1

        assert persister.add_payload.call_count == 1
        assert persister.add_payload.call_args_list[0][1]["module"] == "htaccess"
        assert persister.add_payload.call_args_list[0][1]["category"] == "Htaccess Bypass"
        assert persister.add_payload.call_args_list[0][1]["request"].url == "http://perdu.com/admin/"
