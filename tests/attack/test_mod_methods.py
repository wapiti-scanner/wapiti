from asyncio import Event

import httpx
import respx
import pytest

from tests.attack.fake_persister import FakePersister
from wapitiCore.net.web import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_methods import mod_methods
from wapitiCore.language.logger import ConsoleLogger

class FakeLogger(ConsoleLogger):
    def __init__(self):
        super().__init__()
        self.message = ""

    def log_orange(self, fmt_string, *args):
        if fmt_string != "---":
            self.message = fmt_string


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

    persister = FakePersister()

    request = Request("http://perdu.com/")
    request.path_id = 1
    request.status = 200
    request.set_headers({"content-type": "text/html"})
    persister.requests.append(request)

    request = Request("http://perdu.com/dav/")
    request.path_id = 2
    request.status = 200
    request.set_headers({"content-type": "text/html"})
    persister.requests.append(request)

    crawler = AsyncCrawler("http://perdu.com/", timeout=1)
    options = {"timeout": 10, "level": 2}
    logger = FakeLogger()

    module = mod_methods(crawler, persister, logger, options, Event())
    module.verbose = 2
    module.do_get = True
    for request in persister.requests:
        await module.attack(request)

    assert "http://perdu.com/dav/" in logger.message
    await crawler.close()
