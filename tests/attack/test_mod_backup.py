from asyncio import Event

import httpx
import respx
import pytest

from wapitiCore.net.web import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_backup import mod_backup
from tests import AsyncMock


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
    request.set_headers({"content-type": "text/html"})

    crawler = AsyncCrawler("http://perdu.com/", timeout=1)
    options = {"timeout": 10, "level": 2}

    module = mod_backup(crawler, persister, options, Event())
    module.do_get = True
    await module.attack(request)

    assert persister.add_payload.call_args_list[0][1]["module"] == "backup"
    assert persister.add_payload.call_args_list[0][1]["payload_type"] == "vulnerability"
    assert persister.add_payload.call_args_list[0][1]["request"].url == "http://perdu.com/config.php.bak"
    await crawler.close()


@pytest.mark.asyncio
@respx.mock
async def test_false_positive():
    respx.get("http://perdu.com/config.php").mock(return_value=httpx.Response(200, text="Hello there"))
    respx.get(url__startswith="http://perdu.com/").mock(return_value=httpx.Response(200, text="Default webpage"))

    persister = AsyncMock()

    request = Request("http://perdu.com/config.php")
    request.path_id = 1
    request.set_headers({"content-type": "text/html"})

    crawler = AsyncCrawler("http://perdu.com/", timeout=1)
    options = {"timeout": 10, "level": 2}

    module = mod_backup(crawler, persister, options, Event())
    module.do_get = True
    assert not await module.must_attack(request)

    await crawler.close()
