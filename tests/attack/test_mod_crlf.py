from asyncio import Event
from unittest.mock import AsyncMock

import respx
import pytest
import httpx

from wapitiCore.net import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.attack.mod_crlf import ModuleCrlf


@pytest.mark.asyncio
@respx.mock
async def test_whole_stuff():
    # Test attacking all kind of parameter without crashing
    respx.get(url__regex=r"http://perdu\.com/\?a=.*&foo=bar").mock(return_value=httpx.Response(200, text="Hello there"))
    respx.get(url__regex=r"http://perdu.com/\?a=b*&foo=.*wapiti.*").mock(
        return_value=httpx.Response(200, text="Hello there", headers={"wapiti": "whatever version"})
    )

    persister = AsyncMock()

    request = Request("http://perdu.com/?a=b&foo=bar")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleCrlf(crawler, persister, options, Event(), crawler_configuration)
        module.do_get = True
        await module.attack(request)

        assert persister.add_payload.call_count == 1
        assert persister.add_payload.call_args_list[0][1]["module"] == "crlf"
        assert persister.add_payload.call_args_list[0][1]["category"] == "CRLF Injection"
        assert persister.add_payload.call_args_list[0][1]["parameter"] == "foo"
