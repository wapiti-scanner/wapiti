from subprocess import Popen
import os
import sys
from time import sleep
from asyncio import Event
from unittest.mock import AsyncMock

import httpx
import pytest

from wapitiCore.net import Request, Response
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.attack.mod_csrf import ModuleCsrf


@pytest.fixture(autouse=True)
def run_around_tests():
    base_dir = os.path.dirname(sys.modules["wapitiCore"].__file__)
    test_directory = os.path.join(base_dir, "..", "tests/data/csrf/")

    proc = Popen(["php", "-S", "127.0.0.1:65086", "-a", "-t", test_directory])
    sleep(.5)
    yield
    proc.terminate()


@pytest.mark.asyncio
async def test_csrf_cases():
    persister = AsyncMock()
    all_requests = []

    response = Response(
        httpx.Response(status_code=200),
        url="http://127.0.0.1:65086/"
    )

    request = Request("http://127.0.0.1:65086/")
    request.path_id = 1
    all_requests.append((request, response))

    request = Request(
        "http://127.0.0.1:65086/",
        method="POST",
        post_params=[["email", "wapiti2021@mailinator.com"], ["xsrf_token", "weak"]],
    )
    request.path_id = 2
    all_requests.append((request, response))

    request = Request(
        "http://127.0.0.1:65086/?check=true",
        method="POST",
        post_params=[["email", "wapiti2021@mailinator.com"], ["xsrf_token", "weak"]],
    )
    request.path_id = 3
    all_requests.append((request, response))

    request = Request(
        "http://127.0.0.1:65086/?check=true",
        method="POST",
        post_params=[["name", "Obiwan"]],
    )
    request.path_id = 4
    all_requests.append((request, response))

    response = Response(
        httpx.Response(status_code=200, headers={"x-csrf-token": "testestestest"}),
        url="http://127.0.0.1:65086/"
    )

    request = Request("http://127.0.0.1:65086/", method="POST")
    request.path_id = 5
    all_requests.append((request, response))

    response = Response(
        httpx.Response(status_code=200),
        url="http://127.0.0.1:65086/"
    )

    request = Request(
        "http://127.0.0.1:65086/", 
        method="POST",
        post_params=[["name", "Obiwan"]]
    )
    request.set_headers({"x-csrf-token": "testestestest"})
    request.path_id = 6
    all_requests.append((request, response))

    crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:65086/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 1}

        module = ModuleCsrf(crawler, persister, options, Event(), crawler_configuration)
        module.do_post = True
        for request, response in all_requests:
            if await module.must_attack(request, response):
                await module.attack(request, response)
            else:
                # Not attacked because of GET verb
                assert request.path_id == 1

        vulnerabilities = set()
        for call in persister.add_payload.call_args_list:
            vulnerabilities.add((call[1]["request_id"], call[1]["info"]))

        assert vulnerabilities == {
            (2, "CSRF token 'xsrf_token' is not properly checked in backend"),
            (3, "CSRF token 'xsrf_token' might be easy to predict"),
            (4, "Lack of anti CSRF token"),
            (5, "CSRF token 'x-csrf-token' is not properly checked in backend"),
            (6, "CSRF token 'x-csrf-token' is not properly checked in backend"),
        }
