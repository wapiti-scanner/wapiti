from unittest.mock import Mock
from asyncio import Event

import respx
import pytest
import httpx

from tests.attack.fake_persister import FakePersister
from wapitiCore.net.web import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_crlf import mod_crlf

@pytest.mark.asyncio
@respx.mock
async def test_whole_stuff():
    # Test attacking all kind of parameter without crashing
    respx.get(url__regex=r"http://perdu\.com/\?a=.*&foo=bar").mock(return_value=httpx.Response(200, text="Hello there"))
    respx.get(url__regex=r"http://perdu.com/\?a=b*&foo=.*wapiti.*").mock(
        return_value=httpx.Response(200, text="Hello there", headers={"wapiti": "3.0.5 version"})
    )

    persister = FakePersister()

    request = Request("http://perdu.com/?a=b&foo=bar")
    request.path_id = 1

    crawler = AsyncCrawler("http://perdu.com/", timeout=1)
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_crlf(crawler, persister, logger, options, Event())
    module.verbose = 2
    module.do_get = True
    await module.attack(request)

    assert persister.vulnerabilities
    assert persister.vulnerabilities[0]["parameter"] == "foo"
    await crawler.close()
