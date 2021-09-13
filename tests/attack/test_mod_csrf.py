from subprocess import Popen
import os
import sys
from time import sleep
from asyncio import Event

import pytest

from wapitiCore.net.web import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_csrf import mod_csrf
from wapitiCore.language.vulnerability import _
from tests import AsyncMock


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

    request = Request("http://127.0.0.1:65086/")
    request.path_id = 1
    all_requests.append(request)

    request = Request(
        "http://127.0.0.1:65086/",
        method="POST",
        post_params=[["email", "wapiti2021@mailinator.com"], ["xsrf_token", "weak"]],
    )
    request.path_id = 2
    all_requests.append(request)

    request = Request(
        "http://127.0.0.1:65086/?check=true",
        method="POST",
        post_params=[["email", "wapiti2021@mailinator.com"], ["xsrf_token", "weak"]],
    )
    request.path_id = 3
    all_requests.append(request)

    request = Request(
        "http://127.0.0.1:65086/?check=true",
        method="POST",
        post_params=[["name", "Obiwan"]],
    )
    request.path_id = 4
    all_requests.append(request)

    crawler = AsyncCrawler("http://127.0.0.1:65086/", timeout=1)
    options = {"timeout": 10, "level": 1}

    module = mod_csrf(crawler, persister, options, Event())
    module.do_post = True
    for request in all_requests:
        if await module.must_attack(request):
            await module.attack(request)
        else:
            # Not attacked because of GET verb
            assert request.path_id == 1

    vulnerabilities = set()
    for call in persister.add_payload.call_args_list:
        vulnerabilities.add((call[1]["request_id"], call[1]["info"]))

    assert vulnerabilities == {
        (2, _("CSRF token '{}' is not properly checked in backend").format("xsrf_token")),
        (3, _("CSRF token '{}' might be easy to predict").format("xsrf_token")),
        (4, _("Lack of anti CSRF token"))
    }
    await crawler.close()
