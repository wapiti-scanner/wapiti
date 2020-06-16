from unittest.mock import Mock, patch
import re

import responses

from wapitiCore.net.web import Request
from wapitiCore.net.crawler import Crawler
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


@responses.activate
def test_whole_stuff():
    # Test attacking all kind of parameter without crashing
    responses.add(
        responses.GET,
        url="http://perdu.com/",
        body="Default page"
    )

    responses.add(
        responses.GET,
        url="http://perdu.com/admin",
        body="Hello there",
        headers={"Location": "/admin/"},
        status=301
    )

    responses.add(
        responses.GET,
        url="http://perdu.com/admin/",
        body="Hello there"
    )

    responses.add(
        responses.GET,
        url="http://perdu.com/config.inc",
        body="pass = 123456"
    )

    responses.add(
        responses.GET,
        url="http://perdu.com/admin/authconfig.php",
        body="Hello there"
    )

    responses.add(
        responses.GET,
        url=re.compile(r"http://perdu.com/.*"),
        status=404
    )

    persister = FakePersister()

    request = Request("http://perdu.com/")
    request.path_id = 1
    request.set_headers({"content-type": "text/html"})
    persister.requests.append(request)

    crawler = Crawler("http://perdu.com/", timeout=1)
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    with patch(
            "wapitiCore.attack.mod_buster.mod_buster.payloads",
            [("nawak", Flags()), ("admin", Flags()), ("config.inc", Flags()), ("authconfig.php", Flags())]
    ):
        module = mod_buster(crawler, persister, logger, options)
        module.verbose = 2
        module.do_get = True
        for __ in module.attack():
            pass

        assert module.known_dirs == ["http://perdu.com/", "http://perdu.com/admin/"]
        assert module.known_pages == ["http://perdu.com/config.inc", "http://perdu.com/admin/authconfig.php"]
