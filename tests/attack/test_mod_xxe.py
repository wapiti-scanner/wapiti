from unittest.mock import Mock
from subprocess import Popen
import os
import sys
from time import sleep

import pytest

from wapitiCore.net.web import Request
from wapitiCore.net.crawler import Crawler
from wapitiCore.attack.mod_xxe import mod_xxe


class FakePersister:
    def __init__(self):
        self.requests = []
        self.anomalies = set()
        self.vulnerabilities = []

    def get_links(self, path=None, attack_module: str = ""):
        return self.requests

    def add_anomaly(self, request_id: int = -1, category=None, level=0, request=None, parameter="", info=""):
        self.anomalies.add(parameter)

    def add_vulnerability(self, request_id: int = -1, category=None, level=0, request=None, parameter="", info=""):
        if isinstance(request.post_params, str):
            self.vulnerabilities.append(("raw body", request.post_params))
        elif parameter == "QUERY_STRING":
            self.vulnerabilities.append(("QUERY_STRING", ""))
        else:
            for parameter_name, value in request.get_params:
                if parameter_name == parameter:
                    self.vulnerabilities.append((parameter, value))


@pytest.fixture(autouse=True)
def run_around_tests():
    base_dir = os.path.dirname(sys.modules["wapitiCore"].__file__)
    test_directory = os.path.join(base_dir, "..", "tests/data/")

    proc = Popen(["php", "-S", "127.0.0.1:65080", "-a", "-t", test_directory])
    sleep(.5)
    yield
    proc.terminate()


def test_direct_body():
    persister = FakePersister()
    request = Request(
        "http://127.0.0.1:65080/xxe/direct/body.php",
        method="POST",
        post_params=[["placeholder", "yolo"]]
    )
    request.path_id = 42
    persister.requests.append(request)
    crawler = Crawler("http://127.0.0.1:65080/")
    options = {"timeout": 10, "level": 1}
    logger = Mock()

    module = mod_xxe(crawler, persister, logger, options)
    module.do_post = False
    for __ in module.attack():
        pass

    assert len(persister.vulnerabilities)
    assert persister.vulnerabilities[0][0] == "raw body"
    assert "/etc/passwd" in persister.vulnerabilities[0][1]


def test_direct_param():
    persister = FakePersister()
    request = Request("http://127.0.0.1:65080/xxe/direct/param.php?foo=bar&vuln=yolo")
    request.path_id = 42
    persister.requests.append(request)
    crawler = Crawler("http://127.0.0.1:65080/")
    options = {"timeout": 10, "level": 1}
    logger = Mock()

    module = mod_xxe(crawler, persister, logger, options)
    module.do_post = False
    for __ in module.attack():
        pass

    assert len(persister.vulnerabilities)
    assert persister.vulnerabilities[0][0] == "vuln"


def test_direct_query_string():
    persister = FakePersister()
    request = Request("http://127.0.0.1:65080/xxe/direct/qs.php")
    request.path_id = 42
    persister.requests.append(request)
    crawler = Crawler("http://127.0.0.1:65080/")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_xxe(crawler, persister, logger, options)
    module.do_post = False
    for __ in module.attack():
        pass

    assert len(persister.vulnerabilities)
    assert persister.vulnerabilities[0][0] == "QUERY_STRING"


if __name__ == "__main__":
    test_direct_query_string()
