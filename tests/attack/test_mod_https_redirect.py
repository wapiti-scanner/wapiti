from asyncio import Event
from unittest.mock import AsyncMock

import pytest
import httpx
import respx

from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_https_redirect import ModuleHttpsRedirect

@pytest.mark.asyncio
@respx.mock
async def test_no_redirect():
    # Test cases where there is no redirection
    respx.get("http://perdu.com/").mock(httpx.Response(200, text="Hello there"))
    respx.get("https://perdu.com").mock(httpx.Response(200, text="Hello there"))
    respx.post("http://perdu.com/post").mock(httpx.Response(200, text="Hello there"))
    respx.post("https://perdu.com/post").mock(httpx.Response(200, text="Hello there"))

    persister = AsyncMock()
    all_requests = []

    request = Request("https://perdu.com")
    request.path_id = 1
    all_requests.append(request)

    request = Request("https://perdu.com/post", method="POST", post_params=[["a", "b"]])
    request.path_id = 2
    all_requests.append(request)

    crawler_configuration = CrawlerConfiguration(Request("https://perdu.com"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleHttpsRedirect(crawler, persister, options, Event(), crawler_configuration)
        module.do_post = True
        for request in all_requests:
            if not module.finished:
                await module.attack(request)

        assert persister.add_payload.call_count == 2
        for i in range(persister.add_payload.call_count):
            assert persister.add_payload.call_args_list[i][1]["info"] == "No HTTPS redirection"
            assert persister.add_payload.call_args_list[i][1]["request"].method == "GET" if i < 1 else "POST"


@pytest.mark.asyncio
@respx.mock
async def test_redirect_http():
    # Test cases where there are redirections
    respx.get("http://perdu.com/").mock(httpx.Response(301, headers={"Location": "/get"}))
    respx.get("https://perdu.com").mock(httpx.Response(200, text="Hello there"))
    respx.get("http://perdu.com/get").mock(httpx.Response(301, headers={"Location": "https:/perdu.com/"}))
    respx.get("https://perdu.com/get").mock(httpx.Response(200, text="Hello there"))
    respx.post("http://perdu.com/post").mock(httpx.Response(301, headers={"Location": "/get"}))
    respx.post("https://perdu.com/post").mock(httpx.Response(200, text="Hello there"))

    persister = AsyncMock()
    all_requests = []

    request = Request("https://perdu.com")
    request.path_id = 1
    all_requests.append(request)

    request = Request("https://perdu.com/get")
    request.path_id = 2
    all_requests.append(request)

    request = Request("https://perdu.com/post", method="POST", post_params=[["a", "b"]])
    request.path_id = 3
    all_requests.append(request)

    crawler_configuration = CrawlerConfiguration(Request("https://perdu.com"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleHttpsRedirect(crawler, persister, options, Event(), crawler_configuration)
        module.do_post = True
        for request in all_requests:
            if not module.finished:
                await module.attack(request)

        assert persister.add_payload.call_count == 2
        for i in range(persister.add_payload.call_count):
            assert persister.add_payload.call_args_list[i][1]["info"] == "Redirected to HTTP location : /get"
            assert persister.add_payload.call_args_list[i][1]["request"].method == "GET" if i < 1 else "POST"


@pytest.mark.asyncio
@respx.mock
async def test_error_response():
    # Test cases where there are errors
    respx.get("http://perdu.com/").mock(httpx.Response(403, text="Forbidden"))
    respx.get("https://perdu.com").mock(httpx.Response(200, text="Hello there"))
    respx.post("http://perdu.com/post").mock(httpx.Response(500, text="Internal error"))
    respx.post("https://perdu.com/post").mock(httpx.Response(200, text="Hello there"))

    persister = AsyncMock()
    all_requests = []

    request = Request("https://perdu.com")
    request.path_id = 1
    all_requests.append(request)

    request = Request("https://perdu.com/post", method="POST", post_params=[["a", "b"]])
    request.path_id = 2
    all_requests.append(request)

    crawler_configuration = CrawlerConfiguration(Request("https://perdu.com"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleHttpsRedirect(crawler, persister, options, Event(), crawler_configuration)
        module.do_post = True
        for request in all_requests:
            if not module.finished:
                await module.attack(request)

        assert persister.add_payload.call_count == 1
        assert persister.add_payload.call_args_list[0][1]["info"] == \
            "Received a HTTP 500 error in http://perdu.com/post : 500"
        assert persister.add_payload.call_args_list[0][1]["request"].method == "POST"


@pytest.mark.asyncio
@respx.mock
async def test_http_url_provided():
    # Test cases where the provided url is http
    respx.get("http://perdu.com/").mock(httpx.Response(200, text="Hello there"))
    respx.get("http://perdu.com/get").mock(httpx.Response(200, text="Hello there"))

    persister = AsyncMock()
    all_requests = []

    request = Request("http://perdu.com")
    request.path_id = 1
    all_requests.append(request)

    request = Request("http://perdu.com/get")
    request.path_id = 2
    all_requests.append(request)

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleHttpsRedirect(crawler, persister, options, Event(), crawler_configuration)
        module.do_post = True
        for request in all_requests:
            if not module.finished:
                await module.attack(request)

        assert persister.add_payload.call_count == 1
        assert persister.add_payload.call_args_list[0][1]["info"] == "No HTTPS redirection"
        assert persister.add_payload.call_args_list[0][1]["request"].method == "GET"


@pytest.mark.asyncio
@respx.mock
async def test_specific_port_provided():
    # Test cases where the provided port is specific
    respx.get("https://perdu.com:8443/").mock(httpx.Response(200, text="Hello there"))
    respx.get("http://perdu.com:8443/").mock(httpx.Response(400, text="SSL error"))
    respx.get("https://perdu.com:8443/get").mock(httpx.Response(200, text="Hello there"))

    persister = AsyncMock()
    all_requests = []

    request = Request("https://perdu.com:8443")
    request.path_id = 1
    all_requests.append(request)

    request = Request("https://perdu.com:8443/get")
    request.path_id = 2
    all_requests.append(request)

    crawler_configuration = CrawlerConfiguration(Request("https://perdu.com/8443"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleHttpsRedirect(crawler, persister, options, Event(), crawler_configuration)
        module.do_post = True
        for request in all_requests:
            if not module.finished:
                await module.attack(request)

        assert not persister.add_payload.call_count
