from unittest.mock import Mock
from subprocess import Popen
import os
import sys
from time import sleep
import logging

import pytest
import responses

from wapitiCore.net.web import Request
from wapitiCore.net.crawler import Crawler
from wapitiCore.attack.mod_xxe import mod_xxe


logging.basicConfig(level=logging.DEBUG)


class FakePersister:
    def __init__(self):
        self.requests = []
        self.additionals = set()
        self.anomalies = set()
        self.vulnerabilities = []

    def get_links(self, path=None, attack_module: str = ""):
        return self.requests

    def get_forms(self, attack_module: str = ""):
        return [request for request in self.requests if request.method == "POST"]

    def get_path_by_id(self, path_id):
        for request in self.requests:
            if request.path_id == int(path_id):
                return request
        return None

    def add_additional(self, request_id: int = -1, category=None, level=0, request=None, parameter="", info=""):
        self.additionals.add(request)

    def add_anomaly(self, request_id: int = -1, category=None, level=0, request=None, parameter="", info=""):
        self.anomalies.add(parameter)

    def add_vulnerability(self, request_id: int = -1, category=None, level=0, request=None, parameter="", info=""):
        if isinstance(request.post_params, str):
            self.vulnerabilities.append(("raw body", request.post_params))
        elif parameter == "QUERY_STRING":
            self.vulnerabilities.append(("QUERY_STRING", ""))
        else:
            for parameter_name, value in request.get_params + request.file_params:
                if parameter_name == parameter:
                    self.vulnerabilities.append((parameter, value))


@pytest.fixture(autouse=True)
def run_around_tests():
    base_dir = os.path.dirname(sys.modules["wapitiCore"].__file__)
    test_directory = os.path.join(base_dir, "..", "tests/data/")

    proc = Popen(["php", "-S", "127.0.0.1:65084", "-a", "-t", test_directory])
    sleep(.5)
    yield
    proc.terminate()


def test_direct_body():
    persister = FakePersister()
    request = Request(
        "http://127.0.0.1:65084/xxe/direct/body.php",
        method="POST",
        post_params=[["placeholder", "yolo"]]
    )
    request.path_id = 42
    persister.requests.append(request)
    crawler = Crawler("http://127.0.0.1:65084/")
    options = {"timeout": 10, "level": 1}
    logger = Mock()

    module = mod_xxe(crawler, persister, logger, options)

    for __ in module.attack():
        pass

    assert len(persister.vulnerabilities)
    assert persister.vulnerabilities[0][0] == "raw body"
    assert "/etc/passwd" in persister.vulnerabilities[0][1]


def test_direct_param():
    # check for false positives too
    persister = FakePersister()
    request = Request("http://127.0.0.1:65084/xxe/direct/param.php?foo=bar&vuln=yolo")
    request.path_id = 42
    persister.requests.append(request)
    crawler = Crawler("http://127.0.0.1:65084/")
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
    request = Request("http://127.0.0.1:65084/xxe/direct/qs.php")
    request.path_id = 42
    persister.requests.append(request)
    crawler = Crawler("http://127.0.0.1:65084/")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_xxe(crawler, persister, logger, options)
    module.do_post = False
    for __ in module.attack():
        pass

    assert len(persister.vulnerabilities)
    assert persister.vulnerabilities[0][0] == "QUERY_STRING"


def test_direct_upload():
    persister = FakePersister()
    request = Request(
        "http://127.0.0.1:65084/xxe/direct/upload.php",
        file_params=[
            ["foo", ["bar.xml", "<xml>test</xml>"]],
            ["calendar", ["calendar.xml", "<xml>test</xml>"]]
        ]
    )
    request.path_id = 42
    persister.requests.append(request)
    crawler = Crawler("http://127.0.0.1:65084/")
    options = {"timeout": 10, "level": 1}
    logger = Mock()

    module = mod_xxe(crawler, persister, logger, options)

    for __ in module.attack():
        pass

    assert len(persister.vulnerabilities)
    assert persister.vulnerabilities[0][0] == "calendar"


@responses.activate
def test_out_of_band_body():
    persister = FakePersister()
    request = Request(
        "http://127.0.0.1:65084/xxe/outofband/body.php",
        method="POST",
        post_params=[["placeholder", "yolo"]]
    )
    request.path_id = 42
    persister.requests.append(request)
    crawler = Crawler("http://127.0.0.1:65084/")
    options = {
        "timeout": 10,
        "level": 1,
        "external_endpoint": "http://wapiti3.ovh/",
        "internal_endpoint": "http://wapiti3.ovh/"
    }
    logger = Mock()

    module = mod_xxe(crawler, persister, logger, options)

    responses.add(
        responses.GET,
        "http://wapiti3.ovh/get_xxe.php?id=" + module._session_id,
        json={
            "42": {
                "72617720626f6479": [
                    {
                        "date": "2019-08-17T16:52:41+00:00",
                        "url": "https://wapiti3.ovh/xxe_data/yolo/3/72617720626f6479/31337-0-192.168.2.1.txt",
                        "ip": "192.168.2.1",
                        "size": 999,
                        "payload": "linux2"
                    }
                ]
            }
        }
    )

    module.do_post = False
    for __ in module.attack():
        pass

    assert not persister.vulnerabilities
    module.finish()
    assert persister.vulnerabilities
    assert persister.vulnerabilities[0][0] == "raw body"
    assert "linux2" in persister.vulnerabilities[0][1]


@responses.activate
def test_out_of_band_param():
    persister = FakePersister()
    request = Request("http://127.0.0.1:65084/xxe/outofband/param.php?foo=bar&vuln=yolo")
    request.path_id = 7
    persister.requests.append(request)
    crawler = Crawler("http://127.0.0.1:65084/")
    options = {
        "timeout": 10,
        "level": 1,
        "external_endpoint": "http://wapiti3.ovh/",
        "internal_endpoint": "http://wapiti3.ovh/"
    }
    logger = Mock()

    module = mod_xxe(crawler, persister, logger, options)

    responses.add(
        responses.GET,
        "http://wapiti3.ovh/get_xxe.php?id=" + module._session_id,
        json={
            "7": {
                "76756c6e": [
                    {
                        "date": "2019-08-17T16:52:41+00:00",
                        "url": "https://wapiti3.ovh/xxe_data/yolo/7/76756c6e/31337-0-192.168.2.1.txt",
                        "ip": "192.168.2.1",
                        "size": 999,
                        "payload": "linux2"
                    }
                ]
            }
        }
    )

    module.do_post = False
    for __ in module.attack():
        pass

    assert not persister.vulnerabilities
    module.finish()
    assert persister.vulnerabilities
    assert persister.vulnerabilities[0][0] == "vuln"
    assert "linux2" in persister.vulnerabilities[0][1]


@responses.activate
def test_out_of_band_query_string():
    persister = FakePersister()
    request = Request("http://127.0.0.1:65084/xxe/outofband/qs.php")
    request.path_id = 4
    persister.requests.append(request)
    crawler = Crawler("http://127.0.0.1:65084/")
    options = {
        "timeout": 10,
        "level": 2,
        "external_endpoint": "http://wapiti3.ovh/",
        "internal_endpoint": "http://wapiti3.ovh/"
    }
    logger = Mock()

    module = mod_xxe(crawler, persister, logger, options)
    module.do_post = False
    for __ in module.attack():
        pass

    responses.add(
        responses.GET,
        "http://wapiti3.ovh/get_xxe.php?id=" + module._session_id,
        json={
            "4": {
                "51554552595f535452494e47": [
                    {
                        "date": "2019-08-17T16:52:41+00:00",
                        "url": "https://wapiti3.ovh/xxe_data/yolo/4/51554552595f535452494e47/31337-0-192.168.2.1.txt",
                        "ip": "192.168.2.1",
                        "size": 999,
                        "payload": "linux2"
                    }
                ]
            }
        }
    )

    assert not persister.vulnerabilities
    module.finish()

    assert len(persister.vulnerabilities)
    assert persister.vulnerabilities[0][0] == "QUERY_STRING"


@responses.activate
def test_direct_upload():
    persister = FakePersister()
    request = Request(
        "http://127.0.0.1:65084/xxe/outofband/upload.php",
        file_params=[
            ["foo", ["bar.xml", "<xml>test</xml>"]],
            ["calendar", ["calendar.xml", "<xml>test</xml>"]]
        ]
    )
    request.path_id = 8
    persister.requests.append(request)
    crawler = Crawler("http://127.0.0.1:65084/")
    options = {
        "timeout": 10,
        "level": 1,
        "external_endpoint": "http://wapiti3.ovh/",
        "internal_endpoint": "http://wapiti3.ovh/"
    }
    logger = Mock()

    module = mod_xxe(crawler, persister, logger, options)

    for __ in module.attack():
        pass

    responses.add(
        responses.GET,
        "http://wapiti3.ovh/get_xxe.php?id=" + module._session_id,
        json={
            "8": {
                "63616c656e646172": [
                    {
                        "date": "2019-08-17T16:52:41+00:00",
                        "url": "https://wapiti3.ovh/xxe_data/yolo/8/63616c656e646172/31337-0-192.168.2.1.txt",
                        "ip": "192.168.2.1",
                        "size": 999,
                        "payload": "linux2"
                    }
                ]
            }
        }
    )

    assert not persister.vulnerabilities
    module.finish()

    assert len(persister.vulnerabilities)
    assert persister.vulnerabilities[0][0] == "calendar"


if __name__ == "__main__":
    test_direct_query_string()
