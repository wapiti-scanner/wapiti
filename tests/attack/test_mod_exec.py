from subprocess import Popen
import os
import sys
from time import sleep
from asyncio import Event

import pytest
import respx
import httpx

from wapitiCore.net.web import Request
from wapitiCore.language.vulnerability import _
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_exec import mod_exec
from tests import AsyncMock


@pytest.fixture(autouse=True)
def run_around_tests():
    base_dir = os.path.dirname(sys.modules["wapitiCore"].__file__)
    test_directory = os.path.join(base_dir, "..", "tests/data/")

    proc = Popen(["php", "-S", "127.0.0.1:65083", "-a", "-t", test_directory])
    sleep(.5)
    yield
    proc.terminate()


@pytest.mark.asyncio
@respx.mock
async def test_whole_stuff():
    # Test attacking all kind of parameter without crashing
    respx.get(url__regex=r"http://perdu\.com/.*").mock(httpx.Response(200, text="Hello there"))
    respx.post(url__regex=r"http://perdu\.com/.*").mock(httpx.Response(200, text="Hello there"))

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

    module = mod_exec(crawler, persister, options, Event())
    module.do_post = True
    for request in all_requests:
        await module.attack(request)

    assert True
    await crawler.close()


@pytest.mark.asyncio
@respx.mock
async def test_detection():
    respx.get(url__regex=r"http://perdu\.com/\?vuln=.*env.*").mock(
        return_value=httpx.Response(200, text="PATH=/bin:/usr/bin;PWD=/")
    )

    respx.get(url__regex=r"http://perdu\.com/\?vuln=.*").mock(
        return_value=httpx.Response(200, text="Hello there")
    )

    persister = AsyncMock()

    request = Request("http://perdu.com/?vuln=hello")
    request.path_id = 1

    crawler = AsyncCrawler("http://perdu.com/", timeout=1)
    options = {"timeout": 10, "level": 1}

    module = mod_exec(crawler, persister, options, Event())
    await module.attack(request)

    assert persister.add_payload.call_count == 1
    assert persister.add_payload.call_args_list[0][1]["module"] == "exec"
    assert persister.add_payload.call_args_list[0][1]["category"] == _("Command execution")
    assert persister.add_payload.call_args_list[0][1]["request"].get_params == [["vuln", ";env;"]]
    await crawler.close()


@pytest.mark.asyncio
@respx.mock
async def test_blind_detection():

    def timeout_callback(http_request):
        if "sleep" in str(http_request.url):
            raise httpx.ReadTimeout("Read timed out", request=http_request)
        return httpx.Response(200, text="Hello there")

    respx.get(url__regex=r"http://perdu.com/\?vuln=.*").mock(side_effect=timeout_callback)

    persister = AsyncMock()

    request = Request("http://perdu.com/?vuln=hello")
    request.path_id = 2

    crawler = AsyncCrawler("http://perdu.com/", timeout=1)
    options = {"timeout": 1, "level": 1}

    module = mod_exec(crawler, persister, options, Event())
    module.do_post = False

    payloads_until_sleep = 0
    for payload, __ in module.payloads:
        if "sleep" in payload:
            break
        payloads_until_sleep += 1

    await module.attack(request)

    assert persister.add_payload.call_count == 1
    assert persister.add_payload.call_args_list[0][1]["request"].get_params == [['vuln', 'a`sleep 60`']]
    # We should have all payloads till "sleep" ones
    # then 3 requests for the sleep payload (first then two retries to check random lags)
    # then 1 request to check state of original request
    assert respx.calls.call_count == payloads_until_sleep + 3 + 1
    await crawler.close()
