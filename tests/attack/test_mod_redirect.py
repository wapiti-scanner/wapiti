from unittest.mock import Mock
from subprocess import Popen
import os
import sys
from time import sleep

import pytest

from wapitiCore.net.web import Request
from wapitiCore.net.crawler import Crawler
from wapitiCore.attack.mod_redirect import mod_redirect


class FakePersister:
    def __init__(self):
        self.requests = []
        self.anomalies = set()
        self.vulnerabilities = set()

    def get_links(self, path=None, attack_module: str = ""):
        return self.requests

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
