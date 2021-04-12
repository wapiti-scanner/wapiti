from unittest.mock import Mock
from asyncio import Event

import httpx
import respx
import pytest

from tests.attack.fake_persister import FakePersister
from wapitiCore.net.web import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_ssrf import mod_ssrf
from wapitiCore.language.vulnerability import _

@pytest.mark.asyncio
@respx.mock
async def test_whole_stuff():
    # Test attacking all kind of parameter without crashing
    respx.route(host="perdu.com").mock(return_value=httpx.Response(200, text="Hello there"))

    persister = FakePersister()

    request = Request("http://perdu.com/")
    request.path_id = 1
    persister.requests.append(request)

    request = Request("http://perdu.com/?foo=bar")
    request.path_id = 2
    persister.requests.append(request)

    request = Request(
        "http://perdu.com/?foo=bar",
        post_params=[["a", "b"]],
        file_params=[["file", ("calendar.xml", "<xml>Hello there</xml", "application/xml")]]
    )
    request.path_id = 3
    persister.requests.append(request)

    crawler = AsyncCrawler("http://perdu.com/", timeout=1)
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_ssrf(crawler, persister, logger, options, Event())
    module.verbose = 2
    module.do_post = True

    respx.get("https://wapiti3.ovh/get_ssrf.php?session_id=" + module._session_id).mock(
        return_value=httpx.Response(
            200,
            json={
                "3": {
                    "66696c65": [
                        {
                            "date": "2019-08-17T16:52:41+00:00",
                            "url": "https://wapiti3.ovh/ssrf_data/yolo/3/66696c65/31337-0-192.168.2.1.txt",
                            "ip": "192.168.2.1",
                            "method": "GET"
                        }
                    ]
                }
            }
        )
    )

    for request in persister.requests:
        await module.attack(request)

    assert not persister.vulnerabilities
    # We must trigger finish(à normally called by wapiti.py
    await module.finish()

    assert persister.module == "ssrf"
    assert persister.vulnerabilities
    assert persister.vulnerabilities[0]["category"] == _("Server Side Request Forgery")
    assert persister.vulnerabilities[0]["parameter"] == "file"
    file_params = persister.vulnerabilities[0]["request"].file_params
    assert file_params[0][1][0] == "http://external.url/page"
    await crawler.close()
