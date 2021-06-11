from unittest.mock import Mock
from subprocess import Popen
import os
import sys
from time import sleep
from asyncio import Event

import pytest

from tests.attack.fake_persister import FakePersister
from wapitiCore.net.web import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_csrf import mod_csrf
from wapitiCore.language.vulnerability import _

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
    persister = FakePersister()

    request = Request("http://127.0.0.1:65086/")
    request.path_id = 1
    persister.requests.append(request)

    request = Request(
        "http://127.0.0.1:65086/",
        method="POST",
        post_params=[["email", "wapiti2021@mailinator.com"], ["xsrf_token", "weak"]],
    )
    request.path_id = 2
    persister.requests.append(request)

    request = Request(
        "http://127.0.0.1:65086/?check=true",
        method="POST",
        post_params=[["email", "wapiti2021@mailinator.com"], ["xsrf_token", "weak"]],
    )
    request.path_id = 3
    persister.requests.append(request)

    request = Request(
        "http://127.0.0.1:65086/?check=true",
        method="POST",
        post_params=[["name", "Obiwan"]],
    )
    request.path_id = 4
    persister.requests.append(request)

    crawler = AsyncCrawler("http://127.0.0.1:65086/", timeout=1)
    options = {"timeout": 10, "level": 1}
    logger = Mock()

    module = mod_csrf(crawler, persister, logger, options, Event())
    module.do_post = True
    module.verbose = 2
    for request in persister.requests:
        if module.must_attack(request):
            await module.attack(request)
        else:
            # Not attacked because of GET verb
            assert request.path_id == 1

    assert persister.module == "csrf"
    assert persister.vulnerabilities[0]["category"] == _("Cross Site Request Forgery")
    assert persister.vulnerabilities[0]["request_id"] == 2
    assert persister.vulnerabilities[0]["info"] == \
        _("CSRF token '{}' is not properly checked in backend").format("xsrf_token")
    assert persister.vulnerabilities[1]["request_id"] == 3
    assert persister.vulnerabilities[1]["info"] == _("CSRF token '{}' might be easy to predict").format("xsrf_token")
    assert persister.vulnerabilities[2]["request_id"] == 4
    assert persister.vulnerabilities[2]["info"] == _("Lack of anti CSRF token")
    await crawler.close()
