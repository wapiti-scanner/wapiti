from unittest.mock import Mock
from subprocess import Popen
import os
import sys
from time import sleep
import re

import pytest
import responses
from requests.exceptions import ReadTimeout

from wapitiCore.net.web import Request
from wapitiCore.net.crawler import Crawler
from wapitiCore.attack.mod_blindsql import mod_blindsql


class FakePersister:
    def __init__(self):
        self.requests = []
        self.additionals = set()
        self.anomalies = set()
        self.vulnerabilities = []

    def get_links(self, path=None, attack_module: str = ""):
        return self.requests

    def add_additional(self, request_id: int = -1, category=None, level=0, request=None, parameter="", info=""):
        self.additionals.add(parameter)

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

    proc = Popen(["php", "-S", "127.0.0.1:65082", "-a", "-t", test_directory])
    sleep(.5)
    yield
    proc.terminate()


def test_blindsql_detection():
    # It looks like php -S has serious limitations
    # so PHP script should wait a minimum amount of time for the test to succeed
    persister = FakePersister()
    request = Request("http://127.0.0.1:65082/blind_sql.php?foo=bar&vuln1=hello%20there")
    request.path_id = 42
    persister.requests.append(request)
    crawler = Crawler("http://127.0.0.1:65082/", timeout=1)
    options = {"timeout": 1, "level": 1}
    logger = Mock()

    module = mod_blindsql(crawler, persister, logger, options)
    module.do_post = False
    for __ in module.attack():
        pass

    assert persister.vulnerabilities
    assert persister.vulnerabilities[0][0] == "vuln1"
    assert "sleep" in persister.vulnerabilities[0][1]


def test_blindsql_false_positive():
    persister = FakePersister()
    request = Request("http://127.0.0.1:65082/blind_sql.php?vuln2=hello%20there")
    request.path_id = 42
    persister.requests.append(request)
    crawler = Crawler("http://127.0.0.1:65082/", timeout=1)
    options = {"timeout": 1, "level": 1}
    logger = Mock()

    module = mod_blindsql(crawler, persister, logger, options)
    module.do_post = False
    for __ in module.attack():
        pass

    assert not persister.vulnerabilities


@responses.activate
def test_false_positive_request_count():
    responses.add(
        responses.GET,
        # Beware! Responses seems to do a match on regex and not a search, give it full URL
        re.compile(r"http://perdu.com/blind_sql.php\?vuln1=sleep"),
        body=ReadTimeout("Read timed out")
    )

    responses.add(
        responses.GET,
        re.compile(r"http://perdu.com/blind_sql.php\?vuln1=hello"),
        body=ReadTimeout("Read timed out")
    )

    persister = FakePersister()
    request = Request("http://perdu.com/blind_sql.php?vuln1=hello%20there")
    request.path_id = 42
    persister.requests.append(request)
    crawler = Crawler("http://perdu.com/", timeout=1)
    options = {"timeout": 1, "level": 1}
    logger = Mock()

    module = mod_blindsql(crawler, persister, logger, options)
    module.verbose = 2
    module.do_post = False
    for __ in module.attack():
        pass

    # Due to the retry decorator we should have 6 requests here
    # First three to make sure the payload generate timeouts each time
    # then three more requests with timeouts to make sure the original request is a false positive
    assert len(responses.calls) == 6


@responses.activate
def test_true_positive_request_count():
    responses.add(
        responses.GET,
        re.compile(r"http://perdu.com/blind_sql.php\?vuln1=sleep"),
        body=ReadTimeout("Read timed out")
    )

    responses.add(
        responses.GET,
        re.compile(r"http://perdu.com/blind_sql.php\?vuln1=hello"),
        body="Hello there!"
    )

    persister = FakePersister()
    request = Request("http://perdu.com/blind_sql.php?vuln1=hello%20there")
    request.path_id = 42
    persister.requests.append(request)
    crawler = Crawler("http://perdu.com/", timeout=1)
    options = {"timeout": 1, "level": 1}
    logger = Mock()

    module = mod_blindsql(crawler, persister, logger, options)
    module.verbose = 2
    module.do_post = False
    for __ in module.attack():
        pass

    # Four requests should be made there:
    # Three ones due to time-based SQL injection (one for injection, two to be sure)
    # Then one request to verify that the original request doesn't raise a timeout
    assert len(responses.calls) == 4
