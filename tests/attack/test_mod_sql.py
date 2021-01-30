from unittest.mock import Mock
import re

import responses

from wapitiCore.net.web import Request
from wapitiCore.net.crawler import Crawler
from wapitiCore.attack.mod_sql import mod_sql


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


@responses.activate
def test_whole_stuff():
    # Test attacking all kind of parameter without crashing
    responses.add(
        responses.GET,
        re.compile(r"http://perdu.com/"),
        body="Hello there"
    )

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
        file_params=[["file", ["calendar.xml", "<xml>Hello there</xml"]]]
    )
    request.path_id = 3
    persister.requests.append(request)

    crawler = Crawler("http://perdu.com/", timeout=1)
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_sql(crawler, persister, logger, options)
    module.verbose = 2
    module.do_post = True
    for __ in module.attack():
        pass

    assert True


@responses.activate
def test_false_positive():
    responses.add(
        responses.GET,
        url="http://perdu.com/",
        body="You have an error in your SQL syntax"
    )

    persister = FakePersister()

    request = Request("http://perdu.com/?foo=bar")
    request.path_id = 1
    persister.requests.append(request)

    crawler = Crawler("http://perdu.com/", timeout=1)
    options = {"timeout": 10, "level": 1}
    logger = Mock()

    module = mod_sql(crawler, persister, logger, options)
    module.verbose = 2
    module.do_post = True
    for __ in module.attack():
        pass

    assert not persister.vulnerabilities


@responses.activate
def test_true_positive():
    responses.add(
        responses.GET,
        url="http://perdu.com/?foo=bar",
        body="Hi there"
    )

    responses.add(
        responses.GET,
        url=re.compile(r"http://perdu.com/\?foo=.*"),
        body=(
            "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version "
            "for the right syntax to use near '\\\"\\'' at line 1"
        )
    )

    persister = FakePersister()

    request = Request("http://perdu.com/?foo=bar")
    request.path_id = 1
    persister.requests.append(request)

    crawler = Crawler("http://perdu.com/", timeout=1)
    options = {"timeout": 10, "level": 1}
    logger = Mock()

    module = mod_sql(crawler, persister, logger, options)
    module.verbose = 2
    module.do_post = True
    for __ in module.attack():
        pass

    assert persister.vulnerabilities
