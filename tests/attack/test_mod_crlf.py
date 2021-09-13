from asyncio import Event

import respx
import pytest
import httpx

from wapitiCore.net.web import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.language.vulnerability import _
from wapitiCore.attack.mod_crlf import mod_crlf
from tests import AsyncMock


@pytest.mark.asyncio
@respx.mock
async def test_whole_stuff():
    # Test attacking all kind of parameter without crashing
    respx.get(url__regex=r"http://perdu\.com/\?a=.*&foo=bar").mock(return_value=httpx.Response(200, text="Hello there"))
    respx.get(url__regex=r"http://perdu.com/\?a=b*&foo=.*wapiti.*").mock(
        return_value=httpx.Response(200, text="Hello there", headers={"wapiti": "3.0.5 version"})
    )

    persister = AsyncMock()

    request = Request("http://perdu.com/?a=b&foo=bar")
    request.path_id = 1

    crawler = AsyncCrawler("http://perdu.com/", timeout=1)
    options = {"timeout": 10, "level": 2}

    module = mod_crlf(crawler, persister, options, Event())
    module.do_get = True
    await module.attack(request)

    assert persister.add_payload.call_count == 1
    assert persister.add_payload.call_args_list[0][1]["module"] == "crlf"
    assert persister.add_payload.call_args_list[0][1]["category"] == _("CRLF Injection")
    assert persister.add_payload.call_args_list[0][1]["parameter"] == "foo"
    await crawler.close()
