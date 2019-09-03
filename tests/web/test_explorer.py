from subprocess import Popen
import os
import sys
from time import sleep
from collections import deque

import pytest

from wapitiCore.net.crawler import Crawler, Explorer


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
