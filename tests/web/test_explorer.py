from subprocess import Popen
import os
import sys
from time import sleep
from collections import deque
from tempfile import NamedTemporaryFile
from asyncio import Event

import pytest
import respx
import httpx

from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net.explorer import Explorer
from wapitiCore.net import Request
from wapitiCore.net.scope import Scope


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
    crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:65080/"))
    scope = Scope(Request("http://127.0.0.1:65080/"), "folder")
    explorer = Explorer(crawler_configuration, scope, Event())
    start_urls = deque([Request("http://127.0.0.1:65080/")])
    excluded_urls = []
    # We should have root url, huge form page, target and target with POST method
    assert len([__ async for __ in explorer.async_explore(start_urls, excluded_urls)]) == 4

    crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:65080/"))
    explorer = Explorer(crawler_configuration, scope, Event())
    # Exclude huge POST form with limit of parameters
    explorer.qs_limit = 500
    start_urls = deque([Request("http://127.0.0.1:65080/")])
    excluded_urls = []
    # We should have root url, huge form page, target and target with POST method
    assert len([__ async for __ in explorer.async_explore(start_urls, excluded_urls)]) == 3


@pytest.mark.asyncio
async def test_explorer_filtering():
    crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:65080/"))
    scope = Scope(Request("http://127.0.0.1:65080/"), "folder")
    explorer = Explorer(crawler_configuration, scope, Event())
    start_urls = deque([Request("http://127.0.0.1:65080/filters.html")])
    excluded_urls = []
    results = {resource.url async for resource, response in explorer.async_explore(start_urls, excluded_urls)}
    # We should have current URL and JS URL but without query string.
    # CSS URL should be excluded
    assert results == {"http://127.0.0.1:65080/filters.html", "http://127.0.0.1:65080/yolo.js"}


@pytest.mark.asyncio
@respx.mock
async def test_cookies():
    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(200, text="Hello there!", headers={"Set-Cookie": "foo=bar; Path=/"})
    )

    def print_headers_callback(request):
        return httpx.Response(200, json=dict(request.headers))

    respx.get("http://perdu.com/cookies").mock(side_effect=print_headers_callback)

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        response = await crawler.async_get(Request("http://perdu.com/"))
        assert "foo=bar" in response.headers["set-cookie"]
        response = await crawler.async_get(Request("http://perdu.com/cookies"))
        assert "foo=bar" in response.content


@pytest.mark.asyncio
@respx.mock
async def test_drop_cookies():
    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(200, text="Hello there!", headers={"Set-Cookie": "foo=bar; Path=/"})
    )

    def print_headers_callback(request):
        return httpx.Response(200, json=dict(request.headers))

    respx.get("http://perdu.com/cookies").mock(side_effect=print_headers_callback)

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), drop_cookies=True)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
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
    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    scope = Scope(Request("http://perdu.com/"), "folder")
    explorer = Explorer(crawler_configuration, scope, Event())
    # Load on unexisting file
    explorer.load_saved_state(filename)
    assert not explorer._hostnames
    # Modify state, save it
    explorer._hostnames = {"perdu.com"}
    explorer.save_state(filename)
    # State is the same after saving
    assert explorer._hostnames == {"perdu.com"}

    # New empty explorer
    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    explorer = Explorer(crawler_configuration, scope, Event())
    # Load previous state
    explorer.load_saved_state(filename)
    assert explorer._hostnames == {"perdu.com"}
    os.unlink(filename)


@pytest.mark.asyncio
@respx.mock
async def test_explorer_extract_links():
    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), drop_cookies=True)
    scope = Scope(Request("http://perdu.com/"), "folder")
    explorer = Explorer(crawler_configuration, scope, Event())

    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            200,
            text="""<html><body>
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
    )

    request = Request("http://perdu.com/")
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        response = await crawler.async_send(request)
        results = list(explorer.extract_links(response, request))
        # We should get 6 resources as the âth from the form will also be used as url
        assert len(results) == 6


@pytest.mark.asyncio
@respx.mock
async def test_explorer_extract_links_from_js():
    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), drop_cookies=True)
    scope = Scope(Request("http://perdu.com/"), "folder")
    explorer = Explorer(crawler_configuration, scope, Event())

    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            200,
            text="""Hello there!
        <a href="http://perdu.com/index.html"></a>
        <script src="main-es5.1211ab72babef8.js"></script>
        """
        )
    )

    respx.get("http://perdu.com/main-es5.1211ab72babef8.js").mock(
        return_value=httpx.Response(
            200,
            text="""
            AytR: function (e, t, n) {
                'use strict';n.d(t, 'a', (function () {return r}));
                const r = {
                    web: "http://perdu.com/",
                    host: "http://host.perdu.com/",
                    api: "http://perdu.com/api",
                }
            };
            const Ke = [{path: "/admin",submenu: [{path: "/admin/profile",submenu: []},{path: "/admin/users/add",submenu: []}]}],
            Ye = [{path: "/dashboard",submenu: [{path: "/dashboard/results",submenu: []},{path: "/dashboard/result.json",submenu: []}]}];
            router.navigate(["secret", "path"]); router.createUrlTree(["this", "is", "my" + "_path"]);
            router.navigateByUrl(this.url + "/api/admin"); router.parseUrl(this.url + "/test");
            """,
            headers={"content-type": "application/javascript"}
        )
    )

    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        request = Request("http://perdu.com/")
        response = await crawler.async_send(request)
        results = list(explorer.extract_links(response, request))
        assert len(results) == 2

        request = Request("http://perdu.com/main-es5.1211ab72babef8.js")
        response = await crawler.async_send(request)

        results = list(explorer.extract_links(response, request))
        # http://host.perdu.com is out of scope since by default scope is folder
        assert len(results) == 12
        assert Request("http://perdu.com/secret/path", "GET", link_depth=1) in results
