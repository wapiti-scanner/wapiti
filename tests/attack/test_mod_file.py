from unittest.mock import Mock
from subprocess import Popen
import os
import sys
from time import sleep

import pytest

from wapitiCore.net.web import Request
from wapitiCore.net.crawler import Crawler
from wapitiCore.attack.mod_file import mod_file


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


def test_inclusion_detection():
    # Will also test false positive detection
    persister = FakePersister()
    request = Request("http://127.0.0.1:65080/inclusion.php?yolo=nawak&f=toto")
    request.path_id = 42
    persister.requests.append(request)
    crawler = Crawler("http://127.0.0.1:65080/")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_file(crawler, persister, logger, options)
    module.do_post = False
    for __ in module.attack():
        pass

    assert persister.vulnerabilities == [("f", "/etc/services")]


def test_warning_false_positive():
    persister = FakePersister()
    request = Request("http://127.0.0.1:65080/inclusion.php?yolo=warn&f=toto")
    request.path_id = 42
    persister.requests.append(request)
    crawler = Crawler("http://127.0.0.1:65080/")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_file(crawler, persister, logger, options)
    module.do_post = False
    for __ in module.attack():
        pass

    assert persister.vulnerabilities == [("f", "/etc/services")]


def test_no_crash():
    persister = FakePersister()

    request = Request("http://127.0.0.1:65080/empty.html")
    request.path_id = 1
    persister.requests.append(request)

    request = Request(
        "http://127.0.0.1:65080/empty.html?foo=bar",
        post_params=[["x", "y"]],
        file_params=[["file", ["fname", "content"]]]
    )
    request.path_id = 2
    persister.requests.append(request)

    crawler = Crawler("http://127.0.0.1:65080/")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_file(crawler, persister, logger, options)
    module.do_post = False
    for __ in module.attack():
        pass

    assert True


if __name__ == "__main__":
    test_inclusion_detection()
