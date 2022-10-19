from subprocess import Popen
import os
import sys
from time import sleep
import logging
from asyncio import Event
from unittest.mock import AsyncMock

import pytest
import respx
import httpx

from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_xxe import ModuleXxe


logging.basicConfig(level=logging.DEBUG)


@pytest.fixture(autouse=True)
def run_around_tests():
    base_dir = os.path.dirname(sys.modules["wapitiCore"].__file__)
    test_directory = os.path.join(base_dir, "..", "tests/data/")

    proc = Popen(["php", "-S", "127.0.0.1:65084", "-a", "-t", test_directory])
    sleep(.5)
    yield
    proc.terminate()


@pytest.mark.asyncio
async def test_direct_body():
    persister = AsyncMock()
    request = Request(
        "http://127.0.0.1:65084/xxe/direct/body.php",
        method="POST",
        post_params=[["placeholder", "yolo"]]
    )
    request.path_id = 42
    crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:65084/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 1}

        module = ModuleXxe(crawler, persister, options, Event(), crawler_configuration)

        await module.attack(request)

        assert persister.add_payload.call_count
        assert persister.add_payload.call_args_list[0][1]["module"] == "xxe"
        assert persister.add_payload.call_args_list[0][1]["category"] == "XML External Entity"
        assert persister.add_payload.call_args_list[0][1]["parameter"] == "raw body"
        assert "/etc/passwd" in persister.add_payload.call_args_list[0][1]["request"].post_params


@pytest.mark.asyncio
async def test_direct_param():
    # check for false positives too
    persister = AsyncMock()
    request = Request("http://127.0.0.1:65084/xxe/direct/param.php?foo=bar&vuln=yolo")
    request.path_id = 42
    crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:65084/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 1}

        module = ModuleXxe(crawler, persister, options, Event(), crawler_configuration)
        module.do_post = False
        await module.attack(request)

        assert persister.add_payload.call_count
        assert persister.add_payload.call_args_list[0][1]["parameter"] == "vuln"


@pytest.mark.asyncio
async def test_direct_query_string():
    persister = AsyncMock()
    request = Request("http://127.0.0.1:65084/xxe/direct/qs.php")
    request.path_id = 42
    crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:65084/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleXxe(crawler, persister, options, Event(), crawler_configuration)
        module.do_post = False
        await module.attack(request)

        assert persister.add_payload.call_count
        assert persister.add_payload.call_args_list[0][1]["parameter"] == "QUERY_STRING"


@pytest.mark.asyncio
@respx.mock
async def test_out_of_band_body():
    respx.route(host="127.0.0.1").pass_through()

    persister = AsyncMock()
    request = Request(
        "http://127.0.0.1:65084/xxe/outofband/body.php",
        method="POST",
        post_params=[["placeholder", "yolo"]]
    )
    request.path_id = 42
    persister.get_path_by_id.return_value = request

    persister.requests.return_value = [request]
    crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:65084/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {
            "timeout": 10,
            "level": 1,
            "external_endpoint": "http://wapiti3.ovh/",
            "internal_endpoint": "http://wapiti3.ovh/"
        }

        module = ModuleXxe(crawler, persister, options, Event(), crawler_configuration)

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

        assert not persister.add_payload.call_count
        await module.finish()
        assert persister.add_payload.call_count
        assert persister.add_payload.call_args_list[0][1]["parameter"] == "raw body"
        assert "linux2" in persister.add_payload.call_args_list[0][1]["request"].post_params


@pytest.mark.asyncio
@respx.mock
async def test_out_of_band_param():
    respx.route(host="127.0.0.1").pass_through()

    persister = AsyncMock()
    request = Request("http://127.0.0.1:65084/xxe/outofband/param.php?foo=bar&vuln=yolo")
    request.path_id = 7
    persister.get_path_by_id.return_value = request
    crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:65084/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {
            "timeout": 10,
            "level": 1,
            "external_endpoint": "http://wapiti3.ovh/",
            "internal_endpoint": "http://wapiti3.ovh/"
        }

        module = ModuleXxe(crawler, persister, options, Event(), crawler_configuration)

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

        assert not persister.add_payload.call_count
        await module.finish()
        assert persister.add_payload.call_count
        assert persister.add_payload.call_args_list[0][1]["parameter"] == "vuln"
        assert "linux2" in dict(persister.add_payload.call_args_list[0][1]["request"].get_params)["vuln"]


@pytest.mark.asyncio
@respx.mock
async def test_out_of_band_query_string():
    respx.route(host="127.0.0.1").pass_through()

    persister = AsyncMock()
    request = Request("http://127.0.0.1:65084/xxe/outofband/qs.php")
    request.path_id = 4
    persister.get_path_by_id.return_value = request
    crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:65084/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {
            "timeout": 10,
            "level": 2,
            "external_endpoint": "http://wapiti3.ovh/",
            "internal_endpoint": "http://wapiti3.ovh/"
        }

        module = ModuleXxe(crawler, persister, options, Event(), crawler_configuration)
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

        assert not persister.add_payload.call_count
        await module.finish()

        assert persister.add_payload.call_count
        assert persister.add_payload.call_args_list[0][1]["parameter"] == "QUERY_STRING"


@pytest.mark.asyncio
@respx.mock
async def test_direct_upload():
    respx.route(host="127.0.0.1").pass_through()
    persister = AsyncMock()
    request = Request(
        "http://127.0.0.1:65084/xxe/outofband/upload.php",
        file_params=[
            ["foo", ("bar.xml", b"<xml>test</xml>", "application/xml")],
            ["calendar", ("calendar.xml", b"<xml>test</xml>", "application/xml")]
        ]
    )
    request.path_id = 8
    persister.get_path_by_id.return_value = request
    crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:65084/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {
            "timeout": 10,
            "level": 1,
            "external_endpoint": "http://wapiti3.ovh/",
            "internal_endpoint": "http://wapiti3.ovh/"
        }

        module = ModuleXxe(crawler, persister, options, Event(), crawler_configuration)

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

        assert not persister.add_payload.call_count
        await module.finish()

        assert persister.add_payload.call_count
        assert persister.add_payload.call_args_list[0][1]["parameter"] == "calendar"
