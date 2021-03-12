from subprocess import Popen
import os
import sys
from time import sleep
from collections import deque
import json
from tempfile import NamedTemporaryFile

import pytest
import responses

from wapitiCore.net.crawler import Crawler, Explorer
from wapitiCore.net.web import Request


@pytest.fixture(autouse=True)
def run_around_tests():
    base_dir = os.path.dirname(sys.modules["wapitiCore"].__file__)
    test_directory = os.path.join(base_dir, "..", "tests/data/explorer/")

    proc = Popen(["php", "-S", "127.0.0.1:65080", "-a", "-t", test_directory])
    sleep(.5)
    yield
    proc.terminate()


def test_qs_limit():
    crawler = Crawler("http://127.0.0.1:65080/")
    explorer = Explorer(crawler)
    start_urls = deque(["http://127.0.0.1:65080/"])
    excluded_urls = []
    # We should have root url, huge form page, target and target with POST method
    assert len(list(explorer.explore(start_urls, excluded_urls))) == 4

    crawler = Crawler("http://127.0.0.1:65080/")
    explorer = Explorer(crawler)
    # Exclude huge POST form with limit of parameters
    explorer.qs_limit = 500
    start_urls = deque(["http://127.0.0.1:65080/"])
    excluded_urls = []
    # We should have root url, huge form page, target and target with POST method
    assert len(list(explorer.explore(start_urls, excluded_urls))) == 3


def test_explorer_filtering():
    crawler = Crawler("http://127.0.0.1:65080/")
    explorer = Explorer(crawler)
    start_urls = deque(["http://127.0.0.1:65080/filters.html"])
    excluded_urls = []
    results = set([resource.url for resource in explorer.explore(start_urls, excluded_urls)])
    # We should have current URL and JS URL but without query string.
    # CSS URL should be excluded
    assert results == {"http://127.0.0.1:65080/filters.html", "http://127.0.0.1:65080/yolo.js"}


@responses.activate
def test_cookies():
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

    crawler = Crawler("http://perdu.com/")
    response = crawler.get(Request("http://perdu.com/"))
    assert "foo=bar" in response.headers["set-cookie"]
    response = crawler.get(Request("http://perdu.com/cookies"))
    assert "foo=bar" in response.content


@responses.activate
def test_drop_cookies():
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

    crawler = Crawler("http://perdu.com/")
    crawler.set_drop_cookies()
    response = crawler.get(Request("http://perdu.com/"))
    assert "foo=bar" in response.headers["set-cookie"]
    response = crawler.get(Request("http://perdu.com/cookies"))
    assert "foo=bar" not in response.content


def test_save_and_restore_state():
    # Create a temporary file
    temp_file = NamedTemporaryFile(suffix=".pkl")
    # Get its names
    filename = temp_file.name
    # Delete it
    temp_file.close()
    explorer = Explorer(None)
    # Load on unexisting file
    explorer.load_saved_state(filename)
    assert not explorer._hostnames
    # Modify state, save it
    explorer._hostnames = {"perdu.com"}
    explorer.save_state(filename)
    # State is the same after saving
    assert explorer._hostnames == {"perdu.com"}

    # New tempty explorer
    explorer = Explorer(None)
    # Load previous state
    explorer.load_saved_state(filename)
    assert explorer._hostnames == {"perdu.com"}
    os.unlink(filename)
