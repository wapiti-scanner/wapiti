from asyncio import Event
from unittest.mock import Mock

import httpx
import respx
import pytest

from wapitiCore.net.web import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_methods import mod_methods
from tests import AsyncMock


@pytest.mark.asyncio
@respx.mock
async def test_whole_stuff():
    # Test attacking all kind of parameter without crashing
    respx.options("http://perdu.com/").mock(
        return_value=httpx.Response(200, text="Default page", headers={"Allow": "GET,POST,HEAD"})
    )

    respx.options("http://perdu.com/dav/").mock(
        return_value=httpx.Response(200, text="Private section", headers={"Allow": "GET,POST,HEAD,PUT"})
    )

    persister = AsyncMock()
    all_requests = []

    request = Request("http://perdu.com/")
    request.path_id = 1
    request.status = 200
    request.set_headers({"content-type": "text/html"})
    all_requests.append(request)

    request = Request("http://perdu.com/dav/")
    request.path_id = 2
    request.status = 200
    request.set_headers({"content-type": "text/html"})
    all_requests.append(request)

    crawler = AsyncCrawler("http://perdu.com/", timeout=1)
    options = {"timeout": 10, "level": 2}

    module = mod_methods(crawler, persister, options, Event())
    module.do_get = True
    for request in all_requests:
        await module.attack(request)

    assert persister.add_payload.call_count == 1
    assert "http://perdu.com/dav/" in persister.add_payload.call_args_list[0][1]["info"]
    await crawler.close()
