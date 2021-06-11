from unittest.mock import Mock
from subprocess import Popen
import os
import sys
from time import sleep
import logging
from asyncio import Event

import pytest
import respx
import httpx

from tests.attack.fake_persister import FakePersister
from wapitiCore.net.web import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_xxe import mod_xxe
from wapitiCore.language.vulnerability import _

logging.basicConfig(level=logging.DEBUG)

@pytest.fixture(autouse=True)
def run_around_tests():
    base_dir = os.path.dirname(sys.modules["wapitiCore"].__file__)
    test_directory = os.path.join(base_dir, "..", "tests/data/")

    proc = Popen(["php7.4", "-S", "127.0.0.1:65084", "-a", "-t", test_directory])
    sleep(.5)
    yield
    proc.terminate()


@pytest.mark.asyncio
async def test_direct_body():
    persister = FakePersister()
    request = Request(
        "http://127.0.0.1:65084/xxe/direct/body.php",
        method="POST",
        post_params=[["placeholder", "yolo"]]
    )
    request.path_id = 42
    crawler = AsyncCrawler("http://127.0.0.1:65084/")
    options = {"timeout": 10, "level": 1}
    logger = Mock()

    module = mod_xxe(crawler, persister, logger, options, Event())

    await module.attack(request)

    assert persister.module == "xxe"
    assert len(persister.vulnerabilities)
    assert persister.vulnerabilities[0]["category"] == _("XML External Entity")
    assert persister.vulnerabilities[0]["parameter"] == "raw body"
    assert "/etc/passwd" in persister.vulnerabilities[0]["request"].post_params
    await crawler.close()


@pytest.mark.asyncio
async def test_direct_param():
    # check for false positives too
    persister = FakePersister()
    request = Request("http://127.0.0.1:65084/xxe/direct/param.php?foo=bar&vuln=yolo")
    request.path_id = 42
    crawler = AsyncCrawler("http://127.0.0.1:65084/")
    options = {"timeout": 10, "level": 1}
    logger = Mock()

    module = mod_xxe(crawler, persister, logger, options, Event())
    module.do_post = False
    await module.attack(request)

    assert len(persister.vulnerabilities)
    assert persister.vulnerabilities[0]["parameter"] == "vuln"
    await crawler.close()


@pytest.mark.asyncio
async def test_direct_query_string():
    persister = FakePersister()
    request = Request("http://127.0.0.1:65084/xxe/direct/qs.php")
    request.path_id = 42
    crawler = AsyncCrawler("http://127.0.0.1:65084/")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_xxe(crawler, persister, logger, options, Event())
    module.do_post = False
    await module.attack(request)

    assert len(persister.vulnerabilities)
    assert persister.vulnerabilities[0]["parameter"] == "QUERY_STRING"
    await crawler.close()


@pytest.mark.asyncio
@respx.mock
async def test_out_of_band_body():
    respx.route(host="127.0.0.1").pass_through()

    persister = FakePersister()
    request = Request(
        "http://127.0.0.1:65084/xxe/outofband/body.php",
        method="POST",
        post_params=[["placeholder", "yolo"]]
    )
    request.path_id = 42
    persister.requests.append(request)
    crawler = AsyncCrawler("http://127.0.0.1:65084/")
    options = {
        "timeout": 10,
        "level": 1,
        "external_endpoint": "http://wapiti3.ovh/",
        "internal_endpoint": "http://wapiti3.ovh/"
    }
    logger = Mock()

    module = mod_xxe(crawler, persister, logger, options, Event())

    respx.get("http://wapiti3.ovh/get_xxe.php?session_id=" + module._session_id).mock(
        return_value=httpx.Response(
            200,
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
    )

    module.do_post = False
    await module.attack(request)

    assert not persister.vulnerabilities
    await module.finish()
    assert persister.vulnerabilities
    assert persister.vulnerabilities[0]["parameter"] == "raw body"
    assert "linux2" in persister.vulnerabilities[0]["request"].post_params
    await crawler.close()


@pytest.mark.asyncio
@respx.mock
async def test_out_of_band_param():
    respx.route(host="127.0.0.1").pass_through()

    persister = FakePersister()
    request = Request("http://127.0.0.1:65084/xxe/outofband/param.php?foo=bar&vuln=yolo")
    request.path_id = 7
    persister.requests.append(request)
    crawler = AsyncCrawler("http://127.0.0.1:65084/")
    options = {
        "timeout": 10,
        "level": 1,
        "external_endpoint": "http://wapiti3.ovh/",
        "internal_endpoint": "http://wapiti3.ovh/"
    }
    logger = Mock()

    module = mod_xxe(crawler, persister, logger, options, Event())

    respx.get("http://wapiti3.ovh/get_xxe.php?session_id=" + module._session_id).mock(
        return_value=httpx.Response(
            200,
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
    )

    module.do_post = False
    await module.attack(request)

    assert not persister.vulnerabilities
    await module.finish()
    assert persister.vulnerabilities
    assert persister.vulnerabilities[0]["parameter"] == "vuln"
    assert "linux2" in persister.vulnerabilities[0]["request"].get_params[1][1]
    await crawler.close()


@pytest.mark.asyncio
@respx.mock
async def test_out_of_band_query_string():
    respx.route(host="127.0.0.1").pass_through()

    persister = FakePersister()
    request = Request("http://127.0.0.1:65084/xxe/outofband/qs.php")
    request.path_id = 4
    persister.requests.append(request)
    crawler = AsyncCrawler("http://127.0.0.1:65084/")
    options = {
        "timeout": 10,
        "level": 2,
        "external_endpoint": "http://wapiti3.ovh/",
        "internal_endpoint": "http://wapiti3.ovh/"
    }
    logger = Mock()

    module = mod_xxe(crawler, persister, logger, options, Event())
    module.do_post = False
    await module.attack(request)

    respx.get("http://wapiti3.ovh/get_xxe.php?session_id=" + module._session_id).mock(
        return_value=httpx.Response(
            200,
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
    )

    assert not persister.vulnerabilities
    await module.finish()

    assert len(persister.vulnerabilities)
    assert persister.vulnerabilities[0]["parameter"] == "QUERY_STRING"
    await crawler.close()


@pytest.mark.asyncio
@respx.mock
async def test_direct_upload():
    respx.route(host="127.0.0.1").pass_through()
    persister = FakePersister()
    request = Request(
        "http://127.0.0.1:65084/xxe/outofband/upload.php",
        file_params=[
            ["foo", ("bar.xml", "<xml>test</xml>", "application/xml")],
            ["calendar", ("calendar.xml", "<xml>test</xml>", "application/xml")]
        ]
    )
    request.path_id = 8
    persister.requests.append(request)
    crawler = AsyncCrawler("http://127.0.0.1:65084/")
    options = {
        "timeout": 10,
        "level": 1,
        "external_endpoint": "http://wapiti3.ovh/",
        "internal_endpoint": "http://wapiti3.ovh/"
    }
    logger = Mock()

    module = mod_xxe(crawler, persister, logger, options, Event())

    await module.attack(request)

    respx.get("http://wapiti3.ovh/get_xxe.php?session_id=" + module._session_id).mock(
        return_value=httpx.Response(
            200,
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
    )

    assert not persister.vulnerabilities
    await module.finish()

    assert len(persister.vulnerabilities)
    assert persister.vulnerabilities[0]["parameter"] == "calendar"
    await crawler.close()


if __name__ == "__main__":
    test_direct_query_string()
