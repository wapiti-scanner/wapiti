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
    await crawler.close()

    crawler = AsyncCrawler("http://127.0.0.1:65080/")
    explorer = Explorer(crawler, Event())
    # Exclude huge POST form with limit of parameters
    explorer.qs_limit = 500
    start_urls = deque(["http://127.0.0.1:65080/"])
    excluded_urls = []
    # We should have root url, huge form page, target and target with POST method
    assert len([__ async for __ in explorer.async_explore(start_urls, excluded_urls)]) == 3
    await crawler.close()


@pytest.mark.asyncio
async def test_explorer_filtering():
    crawler = AsyncCrawler("http://127.0.0.1:65080/")
    explorer = Explorer(crawler, Event())
    start_urls = deque(["http://127.0.0.1:65080/filters.html"])
    excluded_urls = []
    results = {resource.url async for resource in explorer.async_explore(start_urls, excluded_urls)}
    # We should have current URL and JS URL but without query string.
    # CSS URL should be excluded
    assert results == {"http://127.0.0.1:65080/filters.html", "http://127.0.0.1:65080/yolo.js"}
    await crawler.close()


@pytest.mark.asyncio
@respx.mock
async def test_cookies():
    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(200, text="Hello there!", headers={"Set-Cookie": "foo=bar; Path=/"})
    )

    def print_headers_callback(request):
        return httpx.Response(200, json=dict(request.headers))

    respx.get("http://perdu.com/cookies").mock(side_effect=print_headers_callback)

    crawler = AsyncCrawler("http://perdu.com/")
    response = await crawler.async_get(Request("http://perdu.com/"))
    assert "foo=bar" in response.headers["set-cookie"]
    response = await crawler.async_get(Request("http://perdu.com/cookies"))
    assert "foo=bar" in response.content
    await crawler.close()


@pytest.mark.asyncio
@respx.mock
async def test_drop_cookies():
    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(200, text="Hello there!", headers={"Set-Cookie": "foo=bar; Path=/"})
    )

    def print_headers_callback(request):
        return httpx.Response(200, json=dict(request.headers))

    respx.get("http://perdu.com/cookies").mock(side_effect=print_headers_callback)

    crawler = AsyncCrawler("http://perdu.com/")
    crawler.drop_cookies = True
    response = await crawler.async_get(Request("http://perdu.com/"))
    assert "foo=bar" in response.headers["set-cookie"]
    response = await crawler.async_get(Request("http://perdu.com/cookies"))
    assert "foo=bar" not in response.content
    await crawler.close()


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
@respx.mock
async def test_explorer_extract_links():
    crawler = AsyncCrawler("http://perdu.com/")
    explorer = Explorer(crawler, Event())

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
    page = await crawler.async_send(request)
    results = list(explorer.extract_links(page, request))
    # We should get 6 resources as the âth from the form will also be used as url
    assert len(results) == 6
    await crawler.close()


@pytest.mark.asyncio
@respx.mock
async def test_explorer_extract_links_from_js():
    crawler = AsyncCrawler("http://perdu.com/")
    explorer = Explorer(crawler, Event())

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

    request = Request("http://perdu.com/")
    page = await crawler.async_send(request)
    results = list(explorer.extract_links(page, request))
    assert len(results) == 2

    request = Request("http://perdu.com/main-es5.1211ab72babef8.js")
    page = await crawler.async_send(request)

    results = list(explorer.extract_links(page, request))
    # http://host.perdu.com is out of scope since by default scope is folder
    assert len(results) == 12
    assert Request("http://perdu.com/secret/path", "GET", link_depth=1) in results
    await crawler.close()
