from unittest.mock import Mock
from subprocess import Popen
import os
import sys
from time import sleep
import re

import pytest
import responses

from wapitiCore.net.web import Request
from wapitiCore.net.crawler import Crawler
from wapitiCore.attack.mod_redirect import mod_redirect


class FakePersister:
    def __init__(self):
        self.requests = []
        self.additionals = set()
        self.anomalies = set()
        self.vulnerabilities = set()

    def get_links(self, path=None, attack_module: str = ""):
        return self.requests

    def add_additional(self, request_id: int = -1, category=None, level=0, request=None, parameter="", info=""):
        self.additionals.add(request)

    def add_anomaly(self, request_id: int = -1, category=None, level=0, request=None, parameter="", info=""):
        self.anomalies.add(parameter)

    def add_vulnerability(self, request_id: int = -1, category=None, level=0, request=None, parameter="", info=""):
        self.vulnerabilities.add(parameter)


@pytest.fixture(autouse=True)
def run_around_tests():
    base_dir = os.path.dirname(sys.modules["wapitiCore"].__file__)
    test_directory = os.path.join(base_dir, "..", "tests/data/")

    proc = Popen(["php", "-S", "127.0.0.1:65080", "-a", "-t", test_directory])
    sleep(.5)
    yield
    proc.terminate()


def test_redirect_detection():
    persister = FakePersister()
    persister.requests.append(Request("http://127.0.0.1:65080/open_redirect.php?yolo=nawak&url=toto"))
    crawler = Crawler("http://127.0.0.1:65080/")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_redirect(crawler, persister, logger, options)
    for __ in module.attack():
        pass

    assert persister.vulnerabilities == {"url"}


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

    module = mod_redirect(crawler, persister, logger, options)
    module.verbose = 2
    module.do_post = True
    for __ in module.attack():
        pass

    assert True
