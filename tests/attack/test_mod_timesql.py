from subprocess import Popen
import os
import sys
from time import sleep
from asyncio import Event
from unittest.mock import AsyncMock

import pytest
import respx
import httpx

from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_timesql import ModuleTimesql


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
    persister = AsyncMock()
    request = Request("http://127.0.0.1:65082/blind_sql.php?foo=bar&vuln1=hello%20there")
    request.path_id = 42
    crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:65082/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        # Time out is set to 0 because in blind_sql.php we have a sleep(2) call
        # and in the module we have ceil(attack_options.get("timeout", self.time_to_sleep)) + 1
        options = {"timeout": 0, "level": 1}

        module = ModuleTimesql(crawler, persister, options, Event(), crawler_configuration)
        module.do_post = False
        await module.attack(request)

        assert persister.add_payload.call_count
        assert persister.add_payload.call_args_list[0][1]["module"] == "timesql"
        assert persister.add_payload.call_args_list[0][1]["category"] == "SQL Injection"
        assert persister.add_payload.call_args_list[0][1]["request"].get_params == [
            ['foo', 'bar'],
            ['vuln1', 'sleep(1)#1']
        ]


@pytest.mark.asyncio
async def test_timesql_false_positive():
    persister = AsyncMock()
    request = Request("http://127.0.0.1:65082/blind_sql.php?vuln2=hello%20there")
    request.path_id = 42
    crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:65082/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        # Time out is set to 0 because in blind_sql.php we have a sleep(2) call
        # and in the module we have ceil(attack_options.get("timeout", self.time_to_sleep)) + 1
        options = {"timeout": 0, "level": 1}

        module = ModuleTimesql(crawler, persister, options, Event(), crawler_configuration)
        module.do_post = False
        await module.attack(request)

        assert not persister.add_payload.call_count


@pytest.mark.asyncio
@respx.mock
async def test_false_positive_request_count():
    respx.get(url__regex=r"http://perdu.com/blind_sql.php\?vuln1=sleep").mock(side_effect=httpx.ReadTimeout)
    respx.get(url__regex=r"http://perdu.com/blind_sql.php\?vuln1=hello").mock(side_effect=httpx.ReadTimeout)

    persister = AsyncMock()
    request = Request("http://perdu.com/blind_sql.php?vuln1=hello%20there")
    request.path_id = 42
    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 1, "level": 1}

        module = ModuleTimesql(crawler, persister, options, Event(), crawler_configuration)
        module.do_post = False
        await module.attack(request)

        # Due to the retry decorator we should have 6 requests here
        # First three to make sure the payload generate timeouts each time
        # then three more requests with timeouts to make sure the original request is a false positive
        assert respx.calls.call_count == 6


@pytest.mark.asyncio
@respx.mock
async def test_true_positive_request_count():
    respx.get(url__regex=r"http://perdu.com/blind_sql\.php\?vuln1=sleep").mock(side_effect=httpx.ReadTimeout)
    respx.get(url__regex=r"http://perdu.com/blind_sql\.php\?vuln1=hello").mock(
        return_value=httpx.Response(200, text="Hello there!")
    )

    persister = AsyncMock()
    request = Request("http://perdu.com/blind_sql.php?vuln1=hello%20there")
    request.path_id = 42
    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 1, "level": 1}

        module = ModuleTimesql(crawler, persister, options, Event(), crawler_configuration)
        module.do_post = False
        await module.attack(request)

        # Four requests should be made there:
        # Three ones due to time-based SQL injection (one for injection, two to be sure)
        # Then one request to verify that the original request doesn't raise a timeout
        assert respx.calls.call_count == 4
