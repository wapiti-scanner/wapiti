from unittest.mock import Mock
from asyncio import Event

import responses
import pytest

from wapitiCore.net.web import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_htaccess import mod_htaccess


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
        self.anomalies.add(request)

    def add_vulnerability(self, request_id: int = -1, category=None, level=0, request=None, parameter="", info=""):
        self.vulnerabilities.append(request)


@pytest.mark.asyncio
@responses.activate
async def test_whole_stuff():
    # Test attacking all kind of parameter without crashing
    responses.add(
        responses.GET,
        url="http://perdu.com/",
        body="Default page"
    )

    responses.add(
        responses.GET,
        url="http://perdu.com/admin/",
        body="Private section",
        status=401
    )

    responses.add(
        "ABC",
        url="http://perdu.com/admin/",
        body="Hello there"
    )

    persister = FakePersister()

    request = Request("http://perdu.com/")
    request.path_id = 1
    request.status = 200
    request.set_headers({"content-type": "text/html"})
    persister.requests.append(request)

    request = Request("http://perdu.com/admin/")
    request.path_id = 2
    request.status = 401
    request.set_headers({"content-type": "text/html"})
    persister.requests.append(request)

    crawler = AsyncCrawler("http://perdu.com/", timeout=1)
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_htaccess(crawler, persister, logger, options, Event())
    module.verbose = 2
    module.do_get = True
    for request in persister.requests:
        if module.must_attack(request):
            await module.attack(request)
        else:
            assert request.path_id == 1

    assert persister.vulnerabilities
    assert persister.vulnerabilities[0].url == "http://perdu.com/admin/"
