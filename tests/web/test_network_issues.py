from subprocess import Popen
import sys
import os
from time import sleep

import pytest
from httpx import ReadTimeout

from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net import Request


@pytest.fixture(autouse=True)
def run_around_tests():
    base_dir = os.path.dirname(sys.modules["wapitiCore"].__file__)
    test_directory = os.path.join(base_dir, "..", "tests/data/")

    proc = Popen(["php", "-S", "127.0.0.1:65080", "-a", "-t", test_directory])
    sleep(.5)
    yield
    proc.terminate()


@pytest.mark.asyncio
async def test_chunked_timeout():
    url = "http://127.0.0.1:65080/chunked_timeout.php"

    request = Request(url)
    crawler_configuration = CrawlerConfiguration(request, timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        with pytest.raises(ReadTimeout):
            await crawler.async_send(request, timeout=1)


@pytest.mark.asyncio
async def test_timeout():
    url = "http://127.0.0.1:65080/timeout.php"

    request = Request(url)
    crawler_configuration = CrawlerConfiguration(request, timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        with pytest.raises(ReadTimeout):
            await crawler.async_send(request, timeout=1)
