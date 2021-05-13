from unittest.mock import Mock
from asyncio import Event

import respx
import pytest
import httpx

from wapitiCore.net.web import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_crlf import mod_crlf


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


@pytest.mark.asyncio
@respx.mock
async def test_whole_stuff():
    # Test attacking all kind of parameter without crashing
    respx.get(url__regex=r"http://perdu\.com/\?a=.*&foo=bar").mock(return_value=httpx.Response(200, text="Hello there"))
    respx.get(url__regex=r"http://perdu.com/\?a=b*&foo=.*wapiti.*").mock(
        return_value=httpx.Response(200, text="Hello there", headers={"wapiti": "3.0.5 version"})
    )

    persister = FakePersister()

    request = Request("http://perdu.com/?a=b&foo=bar")
    request.path_id = 1

    crawler = AsyncCrawler("http://perdu.com/", timeout=1)
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_crlf(crawler, persister, logger, options, Event())
    module.verbose = 2
    module.do_get = True
    await module.attack(request)

    assert persister.vulnerabilities
    assert persister.vulnerabilities[0][0] == "foo"
    await crawler.close()
