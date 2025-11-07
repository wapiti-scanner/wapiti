import asyncio
import json
from collections import deque
from unittest.mock import MagicMock, AsyncMock, patch

import httpx
import pytest
from mitmproxy.http import HTTPFlow, Request as MitmRequest, Response as MitmResponse

from wapitiCore.net import Request
from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net.intercepting_explorer import (
    mitm_to_wapiti_request, MitmFlowToWapitiRequests, launch_headless_explorer, InterceptingExplorer
)
from wapitiCore.net.response import Response
from wapitiCore.net.scope import Scope


class TestInterceptingExplorer:
    @pytest.fixture
    def mitm_request(self):
        req = MitmRequest.make(
            "GET",
            "http://example.com/",
            headers={"Host": "example.com", "Referer": "http://some.referer/"}
        )
        return req

    def test_mitm_to_wapiti_request_get(self, mitm_request):
        wapiti_request = mitm_to_wapiti_request(mitm_request)

        assert isinstance(wapiti_request, Request)
        assert wapiti_request.url == "http://example.com/"
        assert wapiti_request.method == "GET"
        assert wapiti_request.referer == "http://some.referer/"
        assert wapiti_request.post_params == []
        assert wapiti_request.enctype == ""

        expected_headers = httpx.Headers([
            ("host", "example.com"),
            ("referer", "http://some.referer/"),
            ("content-length", "0")
        ])
        assert wapiti_request.headers == expected_headers

    def test_post_urlencoded(self):
        mitm_request = MitmRequest.make(
            "POST",
            "http://example.com/login",
            content=b"user=test&pass=123",
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )

        wapiti_request = mitm_to_wapiti_request(mitm_request)
        assert wapiti_request.method == "POST"
        assert wapiti_request.post_params == [("user", "test"), ("pass", "123")]
        assert wapiti_request.enctype == "application/x-www-form-urlencoded"

    def test_post_json(self):
        json_data = {"key": "value"}
        mitm_request = MitmRequest.make(
            "POST",
            "http://example.com/api",
            content=json.dumps(json_data).encode(),
            headers={"Content-Type": "application/json"}
        )

        wapiti_request = mitm_to_wapiti_request(mitm_request)
        assert wapiti_request.method == "POST"
        assert wapiti_request.post_params == json.dumps(json_data)
        assert wapiti_request.enctype == "application/json"

    def test_post_invalid_json(self):
        mitm_request = MitmRequest.make(
            "POST",
            "http://example.com/api",
            content=b'THISISDOPE',  # Invalid JSON
            headers={"Content-Type": "application/json"}
        )

        wapiti_request = mitm_to_wapiti_request(mitm_request)
        assert wapiti_request is None

    @pytest.fixture
    def flow(self, mitm_request):
        client_conn = MagicMock()
        server_conn = MagicMock()
        flow = HTTPFlow(client_conn, server_conn)
        flow.request = mitm_request
        return flow

    @pytest.mark.asyncio
    async def test_mitm_flow_addon_request(self, flow):
        queue = asyncio.Queue()
        headers = httpx.Headers({"User-Agent": "Wapiti/yolo"})
        scope = Scope(Request("http://example.com"), "folder")
        addon = MitmFlowToWapitiRequests(queue, headers, scope)

        await addon.request(flow)
        assert flow.request.headers["User-Agent"] == "Wapiti/yolo"

    @pytest.mark.asyncio
    async def test_mitm_flow_addon_response(self, flow):
        queue = asyncio.Queue()
        headers = httpx.Headers()
        scope = Scope(Request("http://example.com"), "folder")
        addon = MitmFlowToWapitiRequests(queue, headers, scope)

        flow.response = MitmResponse.make(200, b"Hello", {"Content-Type": "text/html"})
        await addon.response(flow)

        request, response = await queue.get()
        assert isinstance(request, Request)
        assert isinstance(response, Response)
        assert response.content == "Hello"

    @patch("wapitiCore.net.intercepting_explorer.async_playwright")
    @pytest.mark.asyncio
    async def test_launch_headless_explorer(self, mock_async_playwright):
        stop_event = asyncio.Event()
        to_explore = deque()
        to_explore.append(Request("http://example.com"))
        scope = Scope(Request("http://example.com"), "folder")

        mock_page = AsyncMock()
        mock_page.content.return_value = "<html><a href='/page2'>Link</a></html>"
        mock_page.url = "http://example.com/"
        mock_page.query_selector_all.return_value = []

        async def goto_with_delay(*args, **kwargs):
            await asyncio.sleep(0.2)

        mock_page.goto.side_effect = goto_with_delay

        mock_context = AsyncMock()
        mock_context.new_page.return_value = mock_page
        mock_browser = AsyncMock()
        mock_browser.new_context.return_value = mock_context
        mock_playwright = AsyncMock()
        mock_playwright.firefox.launch.return_value = mock_browser
        mock_async_playwright.return_value.__aenter__.return_value = mock_playwright

        mock_crawler = AsyncMock()
        mock_crawler.timeout.connect = 5

        explorer_task = asyncio.create_task(
            launch_headless_explorer(
                stop_event,
                mock_crawler,
                to_explore,
                scope,
                8080,
                [],
                [],
            )
        )

        await asyncio.sleep(0.1)
        stop_event.set()
        await explorer_task

        assert len(to_explore) == 1
        assert to_explore[0].url == "http://example.com/page2"

    @patch("wapitiCore.net.intercepting_explorer.launch_proxy")
    @patch("wapitiCore.net.intercepting_explorer.launch_headless_explorer")
    @pytest.mark.asyncio
    async def test_intercepting_explorer_explore(self, mock_launch_headless, mock_launch_proxy):
        stop_event = asyncio.Event()
        crawler_config = CrawlerConfiguration(Request("http://example.com"))
        scope = Scope(Request("http://example.com"), "folder")
        explorer = InterceptingExplorer(crawler_config, scope, stop_event, headless="hidden")

        async def mock_explore(*args, **kwargs):
            queue = args[1]
            request = Request("http://example.com/test")
            response = Response(httpx.Response(200, text="test"), url="http://example.com/test")
            await queue.put((request, response))
            # In a real scenario, the stop event would be set by another part of the application
            # For this test, we set it after putting one item in the queue.
            stop_event.set()

        mock_launch_proxy.side_effect = mock_explore

        requests = [req async for req, res in explorer.async_explore(deque())]

        assert len(requests) == 1
        assert requests[0].url == "http://example.com/test"
        mock_launch_headless.assert_called_once()
