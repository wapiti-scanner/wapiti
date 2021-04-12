from unittest.mock import Mock
from asyncio import Event

import httpx
import respx
import pytest

from tests.attack.fake_persister import FakePersister
from wapitiCore.net.web import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_backup import mod_backup
from wapitiCore.language.language import _

@pytest.mark.asyncio
@respx.mock
async def test_whole_stuff():
    # Test attacking all kind of parameter without crashing
    respx.get("http://perdu.com/config.php.bak").mock(return_value=httpx.Response(200, text="password = 123456"))
    respx.get("http://perdu.com/config.php").mock(return_value=httpx.Response(200, text="Hello there"))
    respx.get(url__startswith="http://perdu.com/").mock(return_value=httpx.Response(404))

    persister = FakePersister()

    request = Request("http://perdu.com/config.php")
    request.path_id = 1
    request.set_headers({"content-type": "text/html"})

    crawler = AsyncCrawler("http://perdu.com/", timeout=1)
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_backup(crawler, persister, logger, options, Event())
    module.verbose = 2
    module.do_get = True
    await module.attack(request)

    assert persister.module == "backup"
    assert persister.vulnerabilities
    assert persister.vulnerabilities[0]["category"] == _("Backup file")
    assert persister.vulnerabilities[0]["request"].url == "http://perdu.com/config.php.bak"
    await crawler.close()
