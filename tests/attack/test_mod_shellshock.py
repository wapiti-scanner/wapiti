import re
from binascii import unhexlify
from asyncio import Event

import httpx
import respx
import pytest

from wapitiCore.net.web import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.language.vulnerability import _
from wapitiCore.attack.mod_shellshock import mod_shellshock
from tests import AsyncMock


def shellshock_callback(request):
    if "user-agent" in request.headers:
        search = re.search(r"(\\x[0-9a-f]{2})+", request.headers["user-agent"])
        if search:
            hexstring = unhexlify(search.group().replace("\\x", ""))
            return httpx.Response(200, text=hexstring.decode())
    return httpx.Response(200, text="yolo")


@pytest.mark.asyncio
@respx.mock
async def test_whole_stuff():
    respx.get("http://perdu.com/").mock(return_value=httpx.Response(200))

    respx.get(url__regex=r"http://perdu.com/.*").mock(side_effect=shellshock_callback)

    persister = AsyncMock()
    all_requests = []

    request = Request("http://perdu.com/")
    request.path_id = 1
    request.status = 200
    request.set_headers({"content-type": "text/html"})
    all_requests.append(request)

    request = Request("http://perdu.com/vuln/")
    request.path_id = 2
    request.status = 200
    request.set_headers({"content-type": "text/html"})
    all_requests.append(request)

    crawler = AsyncCrawler("http://perdu.com/", timeout=1)
    options = {"timeout": 10, "level": 2}

    module = mod_shellshock(crawler, persister, options, Event())
    module.do_get = True
    for request in all_requests:
        await module.attack(request)

    assert persister.add_payload.call_count == 1
    assert persister.add_payload.call_args_list[0][1]["module"] == "shellshock"
    assert persister.add_payload.call_args_list[0][1]["category"] == _("Command execution")
    assert persister.add_payload.call_args_list[0][1]["request"].url == "http://perdu.com/vuln/"
    await crawler.close()
