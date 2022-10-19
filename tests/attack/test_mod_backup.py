from asyncio import Event
from unittest.mock import AsyncMock

import httpx
import respx
import pytest

from wapitiCore.net import Request, Response
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.attack.mod_backup import ModuleBackup


@pytest.mark.asyncio
@respx.mock
async def test_whole_stuff():
    # Test attacking all kind of parameter without crashing
    respx.get("http://perdu.com/config.php.bak").mock(return_value=httpx.Response(200, text="password = 123456"))
    respx.get("http://perdu.com/config.php").mock(return_value=httpx.Response(200, text="Hello there"))
    respx.get(url__startswith="http://perdu.com/").mock(return_value=httpx.Response(404))

    persister = AsyncMock()

    request = Request("http://perdu.com/config.php")
    request.path_id = 1
    response = Response(
        httpx.Response(
            status_code=200,
            headers={"content-type": "text/html"},
        ),
        url="http://perdu.com/config.php"
    )

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleBackup(crawler, persister, options, Event(), crawler_configuration)
        module.do_get = True
        await module.attack(request, response)

        assert persister.add_payload.call_args_list[0][1]["module"] == "backup"
        assert persister.add_payload.call_args_list[0][1]["payload_type"] == "vulnerability"
        assert persister.add_payload.call_args_list[0][1]["request"].url == "http://perdu.com/config.php.bak"


@pytest.mark.asyncio
@respx.mock
async def test_false_positive():
    respx.get("http://perdu.com/config.php").mock(return_value=httpx.Response(200, text="Hello there"))
    respx.get(url__startswith="http://perdu.com/").mock(return_value=httpx.Response(200, text="Default webpage"))

    persister = AsyncMock()

    request = Request("http://perdu.com/config.php")
    request.path_id = 1
    response = Response(
        httpx.Response(
            status_code=200,
            headers={"content-type": "text/html"},
        ),
        url="http://perdu.com/config.php"
    )

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleBackup(crawler, persister, options, Event(), crawler_configuration)
        module.do_get = True
        assert not await module.must_attack(request, response)
