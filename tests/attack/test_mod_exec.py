from unittest.mock import Mock
from subprocess import Popen
import os
import sys
from time import sleep
from asyncio import Event

import pytest
import respx
import httpx

from wapitiCore.net.web import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_exec import mod_exec


class FakePersister:
    def __init__(self):
        self.requests = []
        self.additionals = set()
        self.anomalies = set()
        self.vulnerabilities = []

    def get_links(self, path=None, attack_module: str = ""):
        return [request for request in self.requests if request.method == "GET"]

    def get_forms(self, attack_module: str = ""):
        return [request for request in self.requests if request.method == "POST"]

    def add_additional(self, request_id: int = -1, category=None, level=0, request=None, parameter="", info=""):
        self.additionals.add(request)

    def add_anomaly(self, request_id: int = -1, category=None, level=0, request=None, parameter="", info=""):
        self.anomalies.add(parameter)

    def add_vulnerability(self, request_id: int = -1, category=None, level=0, request=None, parameter="", info=""):
        for parameter_name, value in request.get_params:
            if parameter_name == parameter:
                self.vulnerabilities.append((parameter, value))


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

    module = mod_exec(crawler, persister, logger, options, Event())
    module.verbose = 2
    module.do_post = True
    for request in persister.requests:
        await module.attack(request)

    assert True


@pytest.mark.asyncio
@respx.mock
async def test_detection():
    respx.get(url__regex=r"http://perdu\.com/\?vuln=.*env.*").mock(
        return_value=httpx.Response(200, text="PATH=/bin:/usr/bin;PWD=/")
    )

    respx.get(url__regex=r"http://perdu\.com/\?vuln=.*").mock(
        return_value=httpx.Response(200, text="Hello there")
    )

    persister = FakePersister()

    request = Request("http://perdu.com/?vuln=hello")
    request.path_id = 1
    persister.requests.append(request)

    crawler = AsyncCrawler("http://perdu.com/", timeout=1)
    options = {"timeout": 10, "level": 1}
    logger = Mock()

    module = mod_exec(crawler, persister, logger, options, Event())
    module.verbose = 2
    await module.attack(request)

    assert persister.vulnerabilities
    assert persister.vulnerabilities[0][0] == "vuln"
    assert "env" in persister.vulnerabilities[0][1]


@pytest.mark.asyncio
@respx.mock
async def test_blind_detection():

    def timeout_callback(http_request):
        if "sleep" in str(http_request.url):
            raise httpx.ReadTimeout("Read timed out", request=http_request)
        return httpx.Response(200, text="Hello there")

    respx.get(url__regex=r"http://perdu.com/\?vuln=.*").mock(side_effect=timeout_callback)

    persister = FakePersister()

    request = Request("http://perdu.com/?vuln=hello")
    request.path_id = 2

    crawler = AsyncCrawler("http://perdu.com/", timeout=1)
    options = {"timeout": 1, "level": 1}
    logger = Mock()

    module = mod_exec(crawler, persister, logger, options, Event())
    module.verbose = 2
    module.do_post = False

    payloads_until_sleep = 0
    for payload, flags in module.payloads:
        if "sleep" in payload:
            break
        payloads_until_sleep += 1

    await module.attack(request)

    assert persister.vulnerabilities
    assert persister.vulnerabilities[0][0] == "vuln"
    assert "sleep" in persister.vulnerabilities[0][1]
    # We should have all payloads till "sleep" ones
    # then 3 requests for the sleep payload (first then two retries to check random lags)
    # then 1 request to check state of original request
    assert respx.calls.call_count == payloads_until_sleep + 3 + 1
