from asyncio import Event

import httpx
import respx
import pytest

from wapitiCore.net.web import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.language.vulnerability import _
from wapitiCore.attack.mod_htaccess import mod_htaccess
from tests import AsyncMock


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
    request.status = 200
    request.set_headers({"content-type": "text/html"})
    all_requests.append(request)

    request = Request("http://perdu.com/admin/")
    request.path_id = 2
    request.status = 401
    request.set_headers({"content-type": "text/html"})
    all_requests.append(request)

    crawler = AsyncCrawler("http://perdu.com/", timeout=1)
    options = {"timeout": 10, "level": 2}

    module = mod_htaccess(crawler, persister, options, Event())
    module.do_get = True
    for request in all_requests:
        if await module.must_attack(request):
            await module.attack(request)
        else:
            assert request.path_id == 1

    assert persister.add_payload.call_count == 1
    assert persister.add_payload.call_args_list[0][1]["module"] == "htaccess"
    assert persister.add_payload.call_args_list[0][1]["category"] == _("Htaccess Bypass")
    assert persister.add_payload.call_args_list[0][1]["request"].url == "http://perdu.com/admin/"
    await crawler.close()
