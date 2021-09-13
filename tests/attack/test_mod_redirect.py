from subprocess import Popen
import os
import sys
from time import sleep
from asyncio import Event

import pytest
import httpx
import respx

from wapitiCore.net.web import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.language.vulnerability import _
from wapitiCore.attack.mod_redirect import mod_redirect
from tests import AsyncMock


@pytest.fixture(autouse=True)
def run_around_tests():
    base_dir = os.path.dirname(sys.modules["wapitiCore"].__file__)
    test_directory = os.path.join(base_dir, "..", "tests/data/")

    proc = Popen(["php", "-S", "127.0.0.1:65080", "-a", "-t", test_directory])
    sleep(.5)
    yield
    proc.terminate()


@pytest.mark.asyncio
async def test_redirect_detection():
    persister = AsyncMock()
    request = Request("http://127.0.0.1:65080/open_redirect.php?yolo=nawak&url=toto")
    crawler = AsyncCrawler("http://127.0.0.1:65080/")
    options = {"timeout": 10, "level": 2}

    module = mod_redirect(crawler, persister, options, Event())
    await module.attack(request)

    assert persister.add_payload.call_args_list[0][1]["module"] == "redirect"
    assert persister.add_payload.call_args_list[0][1]["category"] == _("Open Redirect")
    assert persister.add_payload.call_args_list[0][1]["request"].get_params == [
        ['yolo', 'nawak'],
        ['url', 'https://openbugbounty.org/']
    ]
    await crawler.close()


@pytest.mark.asyncio
@respx.mock
async def test_whole_stuff():
    # Test attacking all kind of parameter without crashing
    respx.route(url__regex=r"http://perdu.com/.*").mock(return_value=httpx.Response(200, text="Hello there"))

    persister = AsyncMock()
    all_requests = []

    request = Request("http://perdu.com/")
    request.path_id = 1
    all_requests.append(request)

    request = Request("http://perdu.com/?foo=bar")
    request.path_id = 2
    all_requests.append(request)

    request = Request(
        "http://perdu.com/?foo=bar",
        post_params=[["a", "b"]],
        file_params=[["file", ("calendar.xml", b"<xml>Hello there</xml", "application/xml")]]
    )
    request.path_id = 3
    all_requests.append(request)

    crawler = AsyncCrawler("http://perdu.com/", timeout=1)
    options = {"timeout": 10, "level": 2}

    module = mod_redirect(crawler, persister, options, Event())
    module.do_post = True
    for request in all_requests:
        await module.attack(request)

    assert True
    await crawler.close()
