from subprocess import Popen
import sys
import os
from time import sleep

import pytest
from httpx import ReadTimeout

from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.net.web import Request


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

    crawler = AsyncCrawler(url, timeout=1)
    request = Request(url)

    with pytest.raises(ReadTimeout):
        await crawler.async_send(request)
    await crawler.close()


@pytest.mark.asyncio
async def test_timeout():
    url = "http://127.0.0.1:65080/timeout.php"

    crawler = AsyncCrawler(url, timeout=1)
    request = Request(url)

    with pytest.raises(ReadTimeout):
        await crawler.async_send(request)
    await crawler.close()
