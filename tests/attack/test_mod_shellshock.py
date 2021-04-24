from unittest.mock import Mock
import re
from binascii import unhexlify
from asyncio import Event

import httpx
import respx
import pytest

from wapitiCore.net.web import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_shellshock import mod_shellshock


class FakePersister:
    def __init__(self):
        self.requests = []
        self.additionals = set()
        self.anomalies = set()
        self.vulnerabilities = []

    def get_links(self, path=None, attack_module: str = ""):
        for request in self.requests:
            if request.method == "GET":
                yield request

    def get_forms(self, attack_module: str = ""):
        return [request for request in self.requests if request.method == "POST"]

    def add_additional(self, request_id: int = -1, category=None, level=0, request=None, parameter="", info=""):
        self.additionals.add(request)

    def add_anomaly(self, request_id: int = -1, category=None, level=0, request=None, parameter="", info=""):
        pass

    def add_vulnerability(self, request_id: int = -1, category=None, level=0, request=None, parameter="", info=""):
        self.vulnerabilities.append((request, info))


def shellshock_callback(request):
    if "user-agent" in request.headers:
        search = re.search(r"(\\x[0-9a-f]{2})+", request.headers["user-agent"])
        if search:
            hexstring = unhexlify(search.group().replace("\\x", ""))
            return httpx.Response(200, text=hexstring.decode())
    return httpx.Response(200, text="yolo")


@pytest.mark.asyncio
@respx.mock
async def test_whole_stuff():
    respx.get("http://perdu.com/").mock(return_value=httpx.Response(200))

    respx.get(url__regex=r"http://perdu.com/.*").mock(side_effect=shellshock_callback)

    persister = FakePersister()

    request = Request("http://perdu.com/")
    request.path_id = 1
    request.status = 200
    request.set_headers({"content-type": "text/html"})
    persister.requests.append(request)

    request = Request("http://perdu.com/vuln/")
    request.path_id = 2
    request.status = 200
    request.set_headers({"content-type": "text/html"})
    persister.requests.append(request)

    crawler = AsyncCrawler("http://perdu.com/", timeout=1)
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_shellshock(crawler, persister, logger, options, Event())
    module.verbose = 2
    module.do_get = True
    for request in persister.requests:
        await module.attack(request)

    assert len(persister.vulnerabilities) == 1
    assert persister.vulnerabilities[0][0].url == (
        "http://perdu.com/vuln/"
    )
    await crawler.close()
