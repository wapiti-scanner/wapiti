from subprocess import Popen
import os
import sys
from time import sleep
from collections import deque
import json
from tempfile import NamedTemporaryFile
from asyncio import Event

import pytest
import responses

from wapitiCore.net.crawler import AsyncCrawler, Explorer
from wapitiCore.net.web import Request


@pytest.fixture(autouse=True)
def run_around_tests():
    base_dir = os.path.dirname(sys.modules["wapitiCore"].__file__)
    test_directory = os.path.join(base_dir, "..", "tests/data/explorer/")

    proc = Popen(["php", "-S", "127.0.0.1:65080", "-a", "-t", test_directory])
    sleep(.5)
    yield
    proc.terminate()


@pytest.mark.asyncio
async def test_qs_limit():
    crawler = AsyncCrawler("http://127.0.0.1:65080/")
    explorer = Explorer(crawler, Event())
    start_urls = deque(["http://127.0.0.1:65080/"])
    excluded_urls = []
    # We should have root url, huge form page, target and target with POST method
    assert len([__ async for __ in explorer.async_explore(start_urls, excluded_urls)]) == 4

    crawler = AsyncCrawler("http://127.0.0.1:65080/")
    explorer = Explorer(crawler, Event())
    # Exclude huge POST form with limit of parameters
    explorer.qs_limit = 500
    start_urls = deque(["http://127.0.0.1:65080/"])
    excluded_urls = []
    # We should have root url, huge form page, target and target with POST method
    assert len([__ async for __ in explorer.async_explore(start_urls, excluded_urls)]) == 3


@pytest.mark.asyncio
async def test_explorer_filtering():
    crawler = AsyncCrawler("http://127.0.0.1:65080/")
    explorer = Explorer(crawler, Event())
    start_urls = deque(["http://127.0.0.1:65080/filters.html"])
    excluded_urls = []
    results = set([resource.url async for resource in explorer.async_explore(start_urls, excluded_urls)])
    # We should have current URL and JS URL but without query string.
    # CSS URL should be excluded
    assert results == {"http://127.0.0.1:65080/filters.html", "http://127.0.0.1:65080/yolo.js"}


@pytest.mark.asyncio
@responses.activate
async def test_cookies():
    responses.add(
        responses.GET,
        "http://perdu.com/",
        body="Hello there!",
        headers={"Set-Cookie": "foo=bar; Path=/"}
    )

    def print_headers_callback(request):
        return 200, {}, json.dumps(dict(request.headers), indent=2)

    responses.add_callback(
        responses.GET,
        "http://perdu.com/cookies",
        callback=print_headers_callback
    )

    crawler = AsyncCrawler("http://perdu.com/")
    response = await crawler.async_get(Request("http://perdu.com/"))
    assert "foo=bar" in response.headers["set-cookie"]
    response = await crawler.async_get(Request("http://perdu.com/cookies"))
    assert "foo=bar" in response.content


@pytest.mark.asyncio
@responses.activate
async def test_drop_cookies():
    responses.add(
        responses.GET,
        "http://perdu.com/",
        body="Hello there!",
        headers={"Set-Cookie": "foo=bar; Path=/"}
    )

    def print_headers_callback(request):
        return 200, {}, json.dumps(dict(request.headers), indent=2)

    responses.add_callback(
        responses.GET,
        "http://perdu.com/cookies",
        callback=print_headers_callback
    )

    crawler = AsyncCrawler("http://perdu.com/")
    crawler.drop_cookies = True
    response = await crawler.async_get(Request("http://perdu.com/"))
    assert "foo=bar" in response.headers["set-cookie"]
    response = await crawler.async_get(Request("http://perdu.com/cookies"))
    assert "foo=bar" not in response.content


def test_save_and_restore_state():
    # Create a temporary file
    temp_file = NamedTemporaryFile(suffix=".pkl")
    # Get its names
    filename = temp_file.name
    # Delete it
    temp_file.close()
    explorer = Explorer(None, Event())
    # Load on unexisting file
    explorer.load_saved_state(filename)
    assert not explorer._hostnames
    # Modify state, save it
    explorer._hostnames = {"perdu.com"}
    explorer.save_state(filename)
    # State is the same after saving
    assert explorer._hostnames == {"perdu.com"}

    # New tempty explorer
    explorer = Explorer(None, Event())
    # Load previous state
    explorer.load_saved_state(filename)
    assert explorer._hostnames == {"perdu.com"}
    os.unlink(filename)


@pytest.mark.asyncio
@responses.activate
async def test_explorer_extract_links():
    crawler = AsyncCrawler("http://perdu.com/")
    explorer = Explorer(crawler, Event())
    responses.add(
        responses.GET,
        "http://perdu.com/",
        body="""<html><body>
        <a href="http://perdu.com/index.html"></a>
        <a href="https://perdu.com/secure_index.html"></a>
        <a href="//perdu.com/protocol_relative.html"></a>
        <a href="//lol.com/protocol_relative.html"></a>
        <a href="http://perdu.com:8000/other_port.html"></a>
        <a href="http://microsoft.com/other_domain.html"></a>
        <a href="welcome.html"></a>
        <a href="/about.html"></a>
        <form method="POST" action="http://perdu.com/valid_form.html">
        <input name="field" type="hidden" value="hello"/></form>
        <form method="POST" action="http://external.com/external_form.html">
        <input name="field" type="hidden" value="hello"/></form>
        """
    )

    request = Request("http://perdu.com/")
    page = await crawler.async_send(request)
    results = list(explorer.extract_links(page, request))
    # We should get 6 resources as the âth from the form will also be used as url
    assert len(results) == 6
