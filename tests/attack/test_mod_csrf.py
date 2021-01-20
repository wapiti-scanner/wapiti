from unittest.mock import Mock
from subprocess import Popen
import os
import sys
from time import sleep

import pytest

from wapitiCore.net.web import Request
from wapitiCore.net.crawler import Crawler
from wapitiCore.attack.mod_csrf import mod_csrf
from wapitiCore.language.vulnerability import _


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
        self.vulnerabilities.append((request_id, info))


@pytest.fixture(autouse=True)
def run_around_tests():
    base_dir = os.path.dirname(sys.modules["wapitiCore"].__file__)
    test_directory = os.path.join(base_dir, "..", "tests/data/csrf/")

    proc = Popen(["php", "-S", "127.0.0.1:65086", "-a", "-t", test_directory])
    sleep(.5)
    yield
    proc.terminate()


def test_csrf_cases():
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

    crawler = Crawler("http://127.0.0.1:65086/", timeout=1)
    options = {"timeout": 10, "level": 1}
    logger = Mock()

    module = mod_csrf(crawler, persister, logger, options)
    module.do_post = True
    module.verbose = 2
    for __ in module.attack():
        pass

    assert set(persister.vulnerabilities) == {
        (2, _("CSRF token '{}' is not properly checked in backend").format("xsrf_token")),
        (3, _("CSRF token '{}' might be easy to predict").format("xsrf_token")),
        (4, _("Lack of anti CSRF token"))
    }
