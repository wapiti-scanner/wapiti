import asyncio
import os
import random
from asyncio import Event
from unittest import mock
from unittest.mock import patch, AsyncMock
from httpx import Response as HttpxResponse

import pytest
import respx
from dns.resolver import Resolver

from tests import get_mock_open
from wapitiCore.attack.attack import VULN
from wapitiCore.attack.mod_log4shell import ModuleLog4Shell
from wapitiCore.language.vulnerability import CRITICAL_LEVEL
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net.response import Response
from wapitiCore.net import Request


@pytest.mark.asyncio
@respx.mock
async def test_read_headers():
    files = {
        "headers.txt": "Header1\nHeader2\n",
        "empty.txt": ""
    }

    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE") or "/home"
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2, "dns_endpoint": "8.8.8.8"}

        module = ModuleLog4Shell(crawler, persister, options, Event(), crawler_configuration)
        module.DATA_DIR = ""

        with mock.patch("builtins.open", get_mock_open(files)) as mock_open_headers:
            module.HEADERS_FILE = "headers.txt"

            headers = await module.read_headers()

            mock_open_headers.assert_called_once()

            assert len(headers) == 2
            assert headers[0] == "Header1"
            assert headers[1] == "Header2"

            module.HEADERS_FILE = "empty.txt"
            headers = await module.read_headers()

            assert len(headers) == 1


@pytest.mark.asyncio
async def test_get_batch_malicious_headers():
    persister = AsyncMock()
    persister.get_root_url.return_value = "http://perdu.com"
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE") or "/home"
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleLog4Shell(crawler, persister, options, Event(), crawler_configuration)

        headers = random.sample(range(0, 100), 100)
        malicious_headers, headers_uuid_record = module._get_batch_malicious_headers(headers)

        assert len(malicious_headers) == 10

        for batch_headers in malicious_headers:
            for header, payload in batch_headers.items():
                assert "${jndi:dns://" + module.dns_endpoint in payload
                assert header in headers
                assert header in headers_uuid_record
                assert str(headers_uuid_record.get(header)) in payload


@pytest.mark.asyncio
@respx.mock
async def test_verify_dns():
    class MockAnswer:
        def __init__(self, response: bool) -> None:
            self.strings = [str(response).lower().encode("utf-8")]

    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE") or "/home"
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2, "dns_endpoint": "dns.google"}

        module = ModuleLog4Shell(crawler, persister, options, Event(), crawler_configuration)

        with mock.patch.object(Resolver, "resolve", return_value=(MockAnswer(True),)):
            assert await module._verify_dns("foobar") is True

        with mock.patch.object(Resolver, "resolve", return_value=(MockAnswer(False),)):
            assert await module._verify_dns("foobar") is False


@pytest.mark.asyncio
@respx.mock
async def test_verify_headers_vuln_found():

    async def mock_verify_dns(_header_uuid: str):
        return True

    # When a vuln has been found
    with patch.object(Request, "http_repr", autospec=True) as mock_http_repr:
        persister = AsyncMock()
        home_dir = os.getenv("HOME") or os.getenv("USERPROFILE") or "/home"
        base_dir = os.path.join(home_dir, ".wapiti")
        persister.CONFIG_DIR = os.path.join(base_dir, "config")

        request = Request("http://perdu.com/")
        request.path_id = 1

        crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
        async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
            options = {"timeout": 10, "level": 2}

            module = ModuleLog4Shell(crawler, persister, options, Event(), crawler_configuration)

            module._verify_dns = mock_verify_dns

            modified_request = Request("http://perdu.com/")
            malicious_headers = {"Header": "payload"}
            headers_uuid_record = {"Header": "unique_id"}

            page = Response(HttpxResponse(200, request=modified_request))

            await module._verify_headers_vulnerability(modified_request, malicious_headers, headers_uuid_record, page)
            mock_http_repr.assert_called_once()
            persister.add_payload.assert_called_once_with(
                request_id=-1,
                payload_type=VULN,
                module="log4shell",
                category="Log4Shell",
                level=CRITICAL_LEVEL,
                request=request,
                parameter="Header: payload",
                info=f"URL {modified_request.url} seems vulnerable to Log4Shell attack by using the header Header",
                wstg=["WSTG-INPV-11"],
                response=page,
            )


@pytest.mark.asyncio
@respx.mock
async def test_verify_headers_vuln_not_found():

    async def mock_verify_dns(_header_uuid: str):
        return False

    #  When no vuln have been found
    with patch.object(Request, "http_repr", autospec=True) as mock_http_repr:

        persister = AsyncMock()
        home_dir = os.getenv("HOME") or os.getenv("USERPROFILE") or "/home"
        base_dir = os.path.join(home_dir, ".wapiti")
        persister.CONFIG_DIR = os.path.join(base_dir, "config")

        request = Request("http://perdu.com/")
        request.path_id = 1

        crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
        async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
            options = {"timeout": 10, "level": 2}

            module = ModuleLog4Shell(crawler, persister, options, Event(), crawler_configuration)

            module._verify_dns = mock_verify_dns

            modified_request = Request("http://perdu.com/")
            malicious_headers = {"Header": "payload"}
            headers_uuid_record = {"Header": "unique_id"}

            page = Response(HttpxResponse(200, request=modified_request))

            await module._verify_headers_vulnerability(modified_request, malicious_headers, headers_uuid_record, page)
            mock_http_repr.assert_not_called()
            persister.add_payload.assert_not_called()


@pytest.mark.asyncio
@respx.mock
async def test_must_attack():
    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE") or "/home"
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleLog4Shell(crawler, persister, options, Event(), crawler_configuration)

        module.finished = False

        assert await module.must_attack(Request("foobar"))

        module.finished = True

        assert not await module.must_attack(Request("foobar"))


@pytest.mark.asyncio
@respx.mock
async def test_attack():
    files = {
        "headers.txt": '\n'.join([str(nbr) for nbr in random.sample(range(0, 100), 100)]),
    }

    persister = AsyncMock()
    persister.get_root_url.return_value = "http://perdu.com/"
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE") or "/home"
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler = AsyncMock()
    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    options = {"timeout": 10, "level": 2}

    request_to_attack = Request("http://perdu.com/", "GET")

    future_verify_dns = asyncio.Future()
    future_verify_dns.set_result(True)

    with mock.patch("builtins.open", get_mock_open(files)) as mock_open_headers, \
        patch.object(ModuleLog4Shell, "_verify_dns", return_value=future_verify_dns) as mock_verify_dns:
        module = ModuleLog4Shell(crawler, persister, options, Event(), crawler_configuration)

        module.DATA_DIR = ""
        module.HEADERS_FILE = "headers.txt"
        await module.attack(request_to_attack)

        mock_open_headers.assert_called_once()

        # vsphere case (2) + each header batch (10) + url case (1) + druid case (1) + solr case (1) + unifi case (2)
        assert crawler.async_send.call_count == 17
        assert mock_verify_dns.call_count == 107


def test_init():
    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE") or "/home"
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler = AsyncMock()
    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))

    # When the dns_endpoint is valid
    options = {"timeout": 10, "level": 2, "dns_endpoint": "whatever.use.mock"}
    with patch("socket.gethostbyname", autospec=True) as mock_gethostbyname:
        module = ModuleLog4Shell(crawler, persister, options, Event(), crawler_configuration)

        assert mock_gethostbyname.assert_called_once
        assert not module.finished

    # When the dns_endpoint is not valid
    options = {"timeout": 10, "level": 2, "dns_endpoint": "256.512.1024.2048"}
    module = ModuleLog4Shell(crawler, persister, options, Event(), crawler_configuration)

    assert module.finished

    # When the dns_endpoint is None
    options = {"timeout": 10, "level": 2, "dns_endpoint": None}
    module = ModuleLog4Shell(crawler, persister, options, Event(), crawler_configuration)

    assert module.finished


@pytest.mark.asyncio
@respx.mock
async def test_attack_apache_struts():
    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE") or "/home"
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler = AsyncMock()
    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    options = {"timeout": 10, "level": 2, "dns_endpoint": None}

    future_url_vulnerability = asyncio.Future()
    future_url_vulnerability.set_result(None)

    with patch.object(
            ModuleLog4Shell,
            "_verify_url_vulnerability",
            return_value=future_url_vulnerability
    ) as mock_verify_url:
        module = ModuleLog4Shell(crawler, persister, options, Event(), crawler_configuration)

        await module._attack_apache_struts("http://perdu.com/")

        assert crawler.async_send.assert_called_once
        assert mock_verify_url.assert_called_once


@pytest.mark.asyncio
@respx.mock
async def test_attack_apache_druid():
    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE") or "/home"
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler = AsyncMock()
    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    options = {"timeout": 10, "level": 2, "dns_endpoint": None}

    future_url_vulnerability = asyncio.Future()
    future_url_vulnerability.set_result(None)

    with patch.object(
            ModuleLog4Shell,
            "_verify_url_vulnerability",
            return_value=future_url_vulnerability
    ) as mock_verify_url:
        module = ModuleLog4Shell(crawler, persister, options, Event(), crawler_configuration)

        await module._attack_apache_druid_url("http://perdu.com/")

        assert crawler.async_send.assert_called_once
        assert mock_verify_url.assert_called_once


@pytest.mark.asyncio
@respx.mock
async def test_attack_unifi():
    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE") or "/home"
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler = AsyncMock()
    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    options = {"timeout": 10, "level": 2, "dns_endpoint": "dns.wapiti3.ovh"}

    future_url_vulnerability = asyncio.Future()
    future_url_vulnerability.set_result(None)

    with patch.object(
            ModuleLog4Shell,
            "_verify_url_vulnerability",
            return_value=future_url_vulnerability
    ) as mock_verify_url:
        module = ModuleLog4Shell(crawler, persister, options, Event(), crawler_configuration)

        await module._attack_unifi_url("http://perdu.com/")

        assert crawler.async_send.assert_called_once
        assert mock_verify_url.assert_called_once
