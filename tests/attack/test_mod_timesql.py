from unittest.mock import Mock
from subprocess import Popen
import os
import sys
from time import sleep
from asyncio import Event

import pytest
import respx
import httpx

from tests.attack.fake_persister import FakePersister
from wapitiCore.net.web import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_timesql import mod_timesql

@pytest.fixture(autouse=True)
def run_around_tests():
    base_dir = os.path.dirname(sys.modules["wapitiCore"].__file__)
    test_directory = os.path.join(base_dir, "..", "tests/data/")

    proc = Popen(["php", "-S", "127.0.0.1:65082", "-a", "-t", test_directory])
    sleep(.5)
    yield
    proc.terminate()


@pytest.mark.asyncio
async def test_timesql_detection():
    # It looks like php -S has serious limitations
    # so PHP script should wait a minimum amount of time for the test to succeed
    persister = FakePersister()
    request = Request("http://127.0.0.1:65082/blind_sql.php?foo=bar&vuln1=hello%20there")
    request.path_id = 42
    crawler = AsyncCrawler("http://127.0.0.1:65082/", timeout=1)
    options = {"timeout": 1, "level": 1}
    logger = Mock()

    module = mod_timesql(crawler, persister, logger, options, Event())
    module.do_post = False
    await module.attack(request)

    assert persister.vulnerabilities
    assert persister.vulnerabilities[0]["parameter"] == "vuln1"
    assert "sleep" in persister.vulnerabilities[0]["request"].get_params[1][1]
    await crawler.close()


@pytest.mark.asyncio
async def test_timesql_false_positive():
    persister = FakePersister()
    request = Request("http://127.0.0.1:65082/blind_sql.php?vuln2=hello%20there")
    request.path_id = 42
    crawler = AsyncCrawler("http://127.0.0.1:65082/", timeout=1)
    options = {"timeout": 1, "level": 1}
    logger = Mock()

    module = mod_timesql(crawler, persister, logger, options, Event())
    module.do_post = False
    await module.attack(request)

    assert not persister.vulnerabilities
    await crawler.close()


@pytest.mark.asyncio
@respx.mock
async def test_false_positive_request_count():
    respx.get(url__regex=r"http://perdu.com/blind_sql.php\?vuln1=sleep").mock(side_effect=httpx.ReadTimeout)
    respx.get(url__regex=r"http://perdu.com/blind_sql.php\?vuln1=hello").mock(side_effect=httpx.ReadTimeout)

    persister = FakePersister()
    request = Request("http://perdu.com/blind_sql.php?vuln1=hello%20there")
    request.path_id = 42
    crawler = AsyncCrawler("http://perdu.com/", timeout=1)
    options = {"timeout": 1, "level": 1}
    logger = Mock()

    module = mod_timesql(crawler, persister, logger, options, Event())
    module.verbose = 2
    module.do_post = False
    await module.attack(request)

    # Due to the retry decorator we should have 6 requests here
    # First three to make sure the payload generate timeouts each time
    # then three more requests with timeouts to make sure the original request is a false positive
    assert respx.calls.call_count == 6
    await crawler.close()


@pytest.mark.asyncio
@respx.mock
async def test_true_positive_request_count():
    respx.get(url__regex=r"http://perdu.com/blind_sql\.php\?vuln1=sleep").mock(side_effect=httpx.ReadTimeout)
    respx.get(url__regex=r"http://perdu.com/blind_sql\.php\?vuln1=hello").mock(
        return_value=httpx.Response(200, text="Hello there!")
    )

    persister = FakePersister()
    request = Request("http://perdu.com/blind_sql.php?vuln1=hello%20there")
    request.path_id = 42
    crawler = AsyncCrawler("http://perdu.com/", timeout=1)
    options = {"timeout": 1, "level": 1}
    logger = Mock()

    module = mod_timesql(crawler, persister, logger, options, Event())
    module.verbose = 2
    module.do_post = False
    await module.attack(request)

    # Four requests should be made there:
    # Three ones due to time-based SQL injection (one for injection, two to be sure)
    # Then one request to verify that the original request doesn't raise a timeout
    assert respx.calls.call_count == 4
    await crawler.close()
