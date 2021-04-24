from unittest.mock import Mock, patch
from asyncio import Event

import httpx
import respx
import pytest

from wapitiCore.net.web import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_buster import mod_buster
from wapitiCore.attack.attack import Flags


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
@respx.mock
async def test_whole_stuff():
    # Test attacking all kind of parameter without crashing
    respx.get("http://perdu.com/").mock(return_value=httpx.Response(200, text="Default page"))
    respx.get("http://perdu.com/admin").mock(
        return_value=httpx.Response(301, text="Hello there", headers={"Location": "/admin/"})
    )
    respx.get("http://perdu.com/admin/").mock(return_value=httpx.Response(200, text="Hello there"))
    respx.get("http://perdu.com/config.inc").mock(return_value=httpx.Response(200, text="pass = 123456"))
    respx.get("http://perdu.com/admin/authconfig.php").mock(return_value=httpx.Response(200, text="Hello there"))
    respx.get(url__regex=r"http://perdu\.com/.*").mock(return_value=httpx.Response(404))

    persister = FakePersister()

    request = Request("http://perdu.com/")
    request.path_id = 1
    request.set_headers({"content-type": "text/html"})
    # Buster module will get requests from the persister
    persister.requests.append(request)

    crawler = AsyncCrawler("http://perdu.com/", timeout=1)
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    with patch(
            "wapitiCore.attack.mod_buster.mod_buster.payloads",
            [("nawak", Flags()), ("admin", Flags()), ("config.inc", Flags()), ("authconfig.php", Flags())]
    ):
        module = mod_buster(crawler, persister, logger, options, Event())
        module.verbose = 2
        module.do_get = True
        await module.attack(request)

        assert module.known_dirs == ["http://perdu.com/", "http://perdu.com/admin/"]
        assert module.known_pages == ["http://perdu.com/config.inc", "http://perdu.com/admin/authconfig.php"]

    await crawler.close()
