import asyncio
from unittest.mock import Mock
from collections import defaultdict
import re

import httpx
import respx
import pytest

from wapitiCore.net.web import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_cookieflags import mod_cookieflags


class FakePersister:
    def __init__(self):
        self.requests = []
        self.additionals = set()
        self.anomalies = set()
        self.vulnerabilities = defaultdict(list)

    def get_links(self, path=None, attack_module: str = ""):
        return [request for request in self.requests if request.method == "GET"]

    def get_forms(self, attack_module: str = ""):
        return [request for request in self.requests if request.method == "POST"]

    def add_additional(self, request_id: int = -1, category=None, level=0, request=None, parameter="", info=""):
        self.additionals.add(request)

    def add_anomaly(self, request_id: int = -1, category=None, level=0, request=None, parameter="", info=""):
        self.anomalies.add(parameter)

    def add_vulnerability(self, request_id: int = -1, category=None, level=0, request=None, parameter="", info=""):
        description, cookie_name = info.split(":")
        self.vulnerabilities[cookie_name.strip()].append(re.search(r"(HttpOnly|Secure)", description).group())


@pytest.mark.asyncio
@respx.mock
async def test_cookieflags():
    respx.get("https://github.com/").mock(
        return_value=httpx.Response(
            200,
            headers=[
                ("set-cookie", "_octo=31337; Path=/; Domain=github.com; Secure; SameSite=Lax"),
                ("set-cookie", "logged_in=no; Path=/; Domain=github.com; HttpOnly; Secure; SameSite=Lax"),
                ("set-cookie", "foo=bar; Path=/; Domain=github.com;")
            ]
        )
    )

    persister = FakePersister()
    request = Request("https://github.com/")
    request.path_id = 1

    crawler = AsyncCrawler("https://github.com/", timeout=1)
    await crawler.async_send(request)  # Put cookies in our crawler object
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_cookieflags(crawler, persister, logger, options, asyncio.Event())
    await module.attack(request)

    assert persister.vulnerabilities
    assert persister.vulnerabilities["foo"] == ["HttpOnly", "Secure"]
    assert persister.vulnerabilities["_octo"] == ["HttpOnly"]
