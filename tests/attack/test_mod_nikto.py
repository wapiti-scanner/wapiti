from unittest.mock import Mock
import re
import os
from asyncio import Event

import httpx
import respx
import pytest

from tests.attack.fake_persister import FakePersister
from wapitiCore.net.web import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_nikto import mod_nikto

@pytest.mark.asyncio
@respx.mock
async def test_whole_stuff():
    # Test attacking all kind of parameter without crashing
    respx.route(host="raw.githubusercontent.com").pass_through()

    respx.get("http://perdu.com/cgi-bin/a1disp3.cgi?../../../../../../../../../../etc/passwd").mock(
        return_value=httpx.Response(200, text="root:0:0:")
    )

    respx.route(host="perdu.com").mock(
        return_value=httpx.Response(404, text="Not found")
    )

    persister = FakePersister()

    request = Request("http://perdu.com/")
    request.path_id = 1
    request.status = 200
    request.set_headers({"content-type": "text/html"})
    persister.requests.append(request)

    crawler = AsyncCrawler("http://perdu.com/", timeout=1)
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_nikto(crawler, persister, logger, options, Event())
    module.verbose = 2
    module.do_get = True
    await module.attack(request)

    assert len(persister.vulnerabilities) == 1
    assert persister.vulnerabilities[0]["request"].url == (
        "http://perdu.com/cgi-bin/a1disp3.cgi?..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd"
    )
    assert "This CGI allows attackers read arbitrary files on the host" in persister.vulnerabilities[0]["info"]
    await crawler.close()
