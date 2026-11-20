import asyncio
import gzip
import json
from collections import deque
from http.cookiejar import CookieJar
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from wapitiCore.net import Request
from wapitiCore.net.async_stickycookie import AsyncStickyCookie
from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net.cookies import mitm_jar_to_cookiejar
from wapitiCore.net.intercepting_explorer import (
    mitm_to_wapiti_request, MitmFlowToWapitiRequests, launch_headless_explorer, launch_proxy, InterceptingExplorer
)
from wapitiCore.net.proxy import Flow, ProxyRequest, ProxyResponse
from wapitiCore.net.response import Response
from wapitiCore.net.scope import Scope


def make_request(method: str, url: str, content: bytes = b"", headers: dict = None) -> ProxyRequest:
    parts = httpx.URL(url)
    return ProxyRequest(
        method=method,
        scheme=parts.scheme,
        host=parts.host,
        port=parts.port or {"http": 80, "https": 443}[parts.scheme],
        target=parts.raw_path.decode(),
        headers=httpx.Headers(headers or {}),
        content=content,
    )


def make_response(status_code: int, content: bytes = b"", headers: dict = None, **kwargs) -> ProxyResponse:
    return ProxyResponse(status_code, httpx.Headers(headers or {}), content, **kwargs)


def make_addon(queue: asyncio.Queue = None, headers: dict = None, drop_cookies: bool = False):
    scope = Scope(Request("http://example.com/"), "folder")
    return MitmFlowToWapitiRequests(queue or asyncio.Queue(), httpx.Headers(headers or {}), scope, drop_cookies)


class TestInterceptingExplorer:
    @pytest.fixture
    def mitm_request(self):
        return make_request(
            "GET",
            "http://example.com/",
            headers={"Host": "example.com", "Referer": "http://some.referer/"}
        )

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
        ])
        assert wapiti_request.headers == expected_headers

    def test_url_with_port_and_query_string(self):
        wapiti_request = mitm_to_wapiti_request(make_request("GET", "https://example.com:8443/search?q=a%20b&x="))
        assert wapiti_request.url == "https://example.com:8443/search?q=a%20b&x="
        assert wapiti_request.get_params == [["q", "a b"], ["x", ""]]

    def test_post_urlencoded(self):
        mitm_request = make_request(
            "POST",
            "http://example.com/login",
            content=b"user=test&pass=1%263&empty=",
            headers={"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}
        )

        wapiti_request = mitm_to_wapiti_request(mitm_request)
        assert wapiti_request.method == "POST"
        assert wapiti_request.post_params == [("user", "test"), ("pass", "1&3"), ("empty", "")]
        assert wapiti_request.enctype == "application/x-www-form-urlencoded; charset=utf-8"

    def test_post_multipart_with_file(self):
        file_content = bytes(range(256)) + b"\r\n--not a boundary\r\n"
        body = (
            b'--XyZ\r\nContent-Disposition: form-data; name="title"\r\n\r\nsome title\r\n'
            b'--XyZ\r\nContent-Disposition: form-data; name="upload"; filename="pic.png"\r\n'
            b"Content-Type: image/png\r\n\r\n" + file_content + b"\r\n"
            b"--XyZ--\r\n"
        )
        mitm_request = make_request(
            "POST",
            "http://example.com/upload",
            content=body,
            headers={"Content-Type": "multipart/form-data; boundary=XyZ"}
        )

        wapiti_request = mitm_to_wapiti_request(mitm_request)
        assert wapiti_request.enctype == "multipart/form-data"
        assert wapiti_request.is_multipart
        assert wapiti_request.post_params == [("title", "some title")]
        # File fields are kept with their name, their type and their exact content
        assert wapiti_request.file_params == [["upload", ("pic.png", file_content, "image/png")]]

    @pytest.mark.parametrize("content_type", ["application/json", "application/json; charset=utf-8"])
    def test_post_json(self, content_type):
        json_data = {"key": "value"}
        mitm_request = make_request(
            "POST",
            "http://example.com/api",
            content=json.dumps(json_data).encode(),
            headers={"Content-Type": content_type}
        )

        wapiti_request = mitm_to_wapiti_request(mitm_request)
        assert wapiti_request.method == "POST"
        assert wapiti_request.post_params == json.dumps(json_data)
        assert wapiti_request.enctype == content_type

    def test_post_invalid_json(self):
        mitm_request = make_request(
            "POST",
            "http://example.com/api",
            content=b'THISISDOPE',  # Invalid JSON
            headers={"Content-Type": "application/json"}
        )

        wapiti_request = mitm_to_wapiti_request(mitm_request)
        assert wapiti_request is None

    def test_post_raw_body(self):
        mitm_request = make_request(
            "POST",
            "http://example.com/soap",
            content=b"<a>b</a>",
            headers={"Content-Type": "text/xml"}
        )

        wapiti_request = mitm_to_wapiti_request(mitm_request)
        assert wapiti_request.post_params == "<a>b</a>"
        assert wapiti_request.enctype == "text/xml"

    @pytest.fixture
    def flow(self, mitm_request):
        return Flow(mitm_request)

    @pytest.mark.asyncio
    async def test_mitm_flow_addon_request(self, flow):
        addon = make_addon(headers={"User-Agent": "Wapiti/yolo", "Accept-Encoding": "gzip, deflate, br"})
        flow.request.headers["Accept-Encoding"] = "gzip, deflate, br, zstd"

        await addon.request(flow)
        assert flow.request.headers["User-Agent"] == "Wapiti/yolo"
        # The browser must not ask for a compression Wapiti is unable to decode
        assert flow.request.headers["Accept-Encoding"] == "gzip, deflate, br"

    @pytest.mark.asyncio
    async def test_mitm_flow_addon_response(self, flow):
        queue = asyncio.Queue()
        addon = make_addon(queue)

        flow.response = make_response(200, b"Hello", {"Content-Type": "text/html"})
        await addon.response(flow)

        request, response = await queue.get()
        assert isinstance(request, Request)
        assert isinstance(response, Response)
        assert response.content == "Hello"

    @pytest.mark.asyncio
    async def test_mitm_flow_addon_compressed_response(self, flow):
        queue = asyncio.Queue()
        addon = make_addon(queue)

        flow.response = make_response(
            200, gzip.compress(b"<html>Hello</html>"), {"Content-Type": "text/html", "Content-Encoding": "gzip"}
        )
        await addon.response(flow)

        __, response = await queue.get()
        assert response.content == "<html>Hello</html>"

    @pytest.mark.asyncio
    async def test_mitm_flow_addon_redirection_keeps_its_body(self, flow):
        queue = asyncio.Queue()
        addon = make_addon(queue)

        flow.response = make_response(
            302, b"<a href='/secret'>moved</a>", {"Content-Type": "text/html", "Location": "/elsewhere"}
        )
        await addon.response(flow)

        __, response = await queue.get()
        assert response.status == 302
        assert response.content == "<a href='/secret'>moved</a>"
        assert flow.response.status_code == 302

    @pytest.mark.asyncio
    async def test_mitm_flow_addon_out_of_scope_redirection(self, flow):
        queue = asyncio.Queue()
        addon = make_addon(queue)

        flow.response = make_response(302, b"", {"Content-Type": "text/html", "Location": "https://evil.example/"})
        await addon.response(flow)

        # The browser is not sent outside the scope and nothing is recorded
        assert queue.empty()
        assert flow.response.status_code == 200
        assert flow.response.media_type == "text/plain"

    @pytest.mark.parametrize(
        "headers",
        [
            {"Content-Type": "application/zip", "Content-Encoding": "gzip"},
            {"Content-Type": "text/html", "Content-Disposition": "attachment; filename=a.html"},
        ],
        ids=["not displayed by browsers", "forced download"]
    )
    @pytest.mark.parametrize("streamed", [False, True])
    @pytest.mark.asyncio
    async def test_mitm_flow_addon_download(self, flow, headers, streamed):
        queue = asyncio.Queue()
        addon = make_addon(queue)

        flow.response = make_response(200, b"" if streamed else b"PK...", headers, streamed=streamed)
        await addon.response(flow)

        assert queue.empty()
        assert flow.response.content == b"Lasciate ogne speranza, voi ch'intrate."
        assert flow.response.media_type == "text/plain"
        # The proxy must send our text, as is, in place of the body of the server
        assert flow.response.streamed is False
        assert "content-encoding" not in flow.response.headers
        assert "content-disposition" not in flow.response.headers

    @pytest.mark.parametrize(
        "response",
        [
            make_response(404, b"Not found", {"Content-Type": "text/html"}),
            make_response(101, b"", {"Upgrade": "websocket", "Connection": "Upgrade"}, streamed=True),
            make_response(200, b"", {"Content-Type": "text/event-stream"}, streamed=True),
            make_response(200, b"", {"Content-Type": "text/html"}, streamed=True),
            make_response(200, b"GIF89a", {"Content-Type": "image/gif"}),
        ],
        ids=["client error", "websocket", "server-sent events", "too big to be kept", "image"]
    )
    @pytest.mark.asyncio
    async def test_mitm_flow_addon_ignored_responses(self, flow, response):
        queue = asyncio.Queue()
        addon = make_addon(queue)
        expected = (response.status_code, response.content, response.streamed, dict(response.headers))

        flow.response = response
        await addon.response(flow)

        # Nothing is recorded and the browser gets the response of the server
        assert queue.empty()
        assert (response.status_code, response.content, response.streamed, dict(response.headers)) == expected

    @pytest.mark.asyncio
    async def test_mitm_flow_addon_drop_cookies(self, flow):
        addon = make_addon(drop_cookies=True)
        flow.response = make_response(200, b"Hello", {"Content-Type": "text/html", "Set-Cookie": "a=b"})
        await addon.response(flow)

        assert "set-cookie" not in flow.response.headers

    @pytest.mark.asyncio
    async def test_sticky_cookies(self):
        jar = CookieJar()
        addon = AsyncStickyCookie(jar)

        flow = Flow(make_request("GET", "https://example.com/app/login"))
        flow.response = ProxyResponse(
            200,
            httpx.Headers([
                ("Set-Cookie", "session=abc; Path=/app; HttpOnly"),
                ("Set-Cookie", "lang=fr; Expires=Wed, 01 Jan 2099 00:00:00 GMT"),
                ("Set-Cookie", "old=1; Max-Age=0"),
                ("Set-Cookie", "other=1; Domain=elsewhere.org"),
            ]),
        )
        await addon.response(flow)
        assert dict(addon.jar) == {
            ("example.com", 443, "/app"): {"session": "abc"},
            ("example.com", 443, "/"): {"lang": "fr"},
        }

        # Cookies are sent back according to their path
        flow = Flow(make_request("GET", "https://example.com/app/account"))
        await addon.request(flow)
        assert sorted(flow.request.headers["cookie"].split("; ")) == ["lang=fr", "session=abc"]

        flow = Flow(make_request("GET", "https://example.com/"))
        await addon.request(flow)
        assert flow.request.headers["cookie"] == "lang=fr"

        flow = Flow(make_request("GET", "https://elsewhere.org/"))
        await addon.request(flow)
        assert "cookie" not in flow.request.headers

        # A cookie is removed when the server expires it
        flow = Flow(make_request("GET", "https://example.com/logout"))
        flow.response = make_response(200, b"", {"Set-Cookie": "lang=; Expires=Thu, 01 Jan 1970 00:00:00 GMT"})
        await addon.response(flow)
        assert dict(addon.jar) == {("example.com", 443, "/app"): {"session": "abc"}}

        cookies = list(mitm_jar_to_cookiejar(addon.jar))
        assert [(cookie.name, cookie.value, cookie.domain, cookie.path) for cookie in cookies] == [
            ("session", "abc", ".example.com", "/app")
        ]

    @pytest.mark.asyncio
    async def test_launch_proxy_records_what_goes_through(self, tmp_path):
        queue = asyncio.Queue()
        scope = Scope(Request("http://127.0.0.1/"), "domain")

        async def handle(reader, writer):
            await reader.readuntil(b"\r\n\r\n")
            body = b"<html><a href='/next'>next</a></html>"
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: sid=42\r\n"
                b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body
            )
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        server_port = server.sockets[0].getsockname()[1]
        with patch("wapitiCore.net.intercepting_explorer.SqlPersister.CONFIG_DIR", str(tmp_path)):
            # Find a free port for the proxy
            probe = await asyncio.start_server(handle, "127.0.0.1", 0)
            proxy_port = probe.sockets[0].getsockname()[1]
            probe.close()
            await probe.wait_closed()

            task = asyncio.create_task(
                launch_proxy(proxy_port, queue, httpx.Headers({"User-Agent": "Wapiti"}), CookieJar(), scope)
            )
            try:
                async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{proxy_port}") as client:
                    for __ in range(50):
                        try:
                            response = await client.get(f"http://127.0.0.1:{server_port}/index?a=b")
                            break
                        except httpx.TransportError:
                            await asyncio.sleep(0.05)
            finally:
                task.cancel()
                jar = await task
                server.close()

        assert response.status_code == 200
        request, wapiti_response = queue.get_nowait()
        assert request.url == f"http://127.0.0.1:{server_port}/index?a=b"
        assert request.headers["user-agent"] == "Wapiti"
        assert "next" in wapiti_response.content
        # The certificate authority was created in the configuration directory
        assert (tmp_path / "ca" / "wapiti-ca.pem").is_file()
        # Cookies seen by the proxy are given back when it stops
        assert dict(jar) == {("127.0.0.1", server_port, "/"): {"sid": "42"}}

    @pytest.mark.asyncio
    async def test_launch_proxy_port_already_used(self, tmp_path):
        stop_event = asyncio.Event()
        busy = await asyncio.start_server(lambda reader, writer: writer.close(), "127.0.0.1", 0)
        busy_port = busy.sockets[0].getsockname()[1]
        try:
            with patch("wapitiCore.net.intercepting_explorer.SqlPersister.CONFIG_DIR", str(tmp_path)):
                scope = Scope(Request("http://example.com/"), "folder")
                jar = await asyncio.wait_for(
                    launch_proxy(
                        busy_port, asyncio.Queue(), httpx.Headers(), CookieJar(), scope, stop_event=stop_event
                    ),
                    timeout=5,
                )
        finally:
            busy.close()

        # The crawl is told to stop instead of waiting for requests that will never come
        assert stop_event.is_set()
        assert not jar

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

        async def goto_with_delay(*args, **kwargs):  # pylint: disable=unused-argument
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

        async def mock_explore(*args, **kwargs):  # pylint: disable=unused-argument
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

    @pytest.mark.parametrize(
        "headless, expected",
        [
            (
                "no",
                "Launching the intercepting proxy on port 8080. "
                "Configure your browser to use it, press ctrl+c when you are done.",
            ),
            ("hidden", "Launching the intercepting proxy on port 8080 for the headless browser."),
        ],
        ids=["interception only", "headless crawler"],
    )
    @patch("wapitiCore.net.intercepting_explorer.log_blue")
    @patch("wapitiCore.net.intercepting_explorer.launch_proxy")
    @patch("wapitiCore.net.intercepting_explorer.launch_headless_explorer")
    @pytest.mark.asyncio
    async def test_proxy_announcement_depends_on_headless_mode(
        self, mock_launch_headless, mock_launch_proxy, mock_log_blue, headless, expected, tmp_path, monkeypatch
    ):
        # pylint: disable=unused-argument,too-many-positional-arguments
        monkeypatch.setattr("wapitiCore.net.intercepting_explorer.SqlPersister.CONFIG_DIR", str(tmp_path))
        # GIVEN an intercepting explorer whose proxy stops the crawl as soon as it starts
        stop_event = asyncio.Event()
        crawler_config = CrawlerConfiguration(Request("http://example.com"))
        scope = Scope(Request("http://example.com"), "folder")
        explorer = InterceptingExplorer(crawler_config, scope, stop_event, mitm_port=8080, headless=headless)

        async def mock_proxy(*args, **kwargs):  # pylint: disable=unused-argument
            stop_event.set()

        mock_launch_proxy.side_effect = mock_proxy

        # WHEN the crawl runs
        _ = [req async for req, __ in explorer.async_explore(deque([Request("http://example.com/")]))]

        # THEN only a user driving the proxy with their own browser is asked to configure it
        mock_log_blue.assert_any_call(expected)
        # AND is told where to find the certificate to import
        certificate_path = str(tmp_path / "ca" / "wapiti-ca.pem")
        announced = any(certificate_path in str(call.args[0]) for call in mock_log_blue.call_args_list)
        assert announced is (headless == "no")

    @patch("wapitiCore.net.intercepting_explorer.AsyncCrawler")
    @patch("wapitiCore.net.intercepting_explorer.launch_proxy")
    @patch("wapitiCore.net.intercepting_explorer.launch_headless_explorer")
    @pytest.mark.asyncio
    async def test_seed_fallback_covers_uncovered_host(
        self, mock_launch_headless, mock_launch_proxy, mock_crawler_cls
    ):
        # GIVEN a headless crawl that captures nothing (e.g. an index returning 403 that the
        # MITM proxy dropped), so no request is produced for the target host
        stop_event = asyncio.Event()
        crawler_config = CrawlerConfiguration(Request("https://example.com/"))
        scope = Scope(Request("https://example.com/"), "folder")
        explorer = InterceptingExplorer(crawler_config, scope, stop_event, headless="hidden")

        async def mock_proxy(*args, **kwargs):  # pylint: disable=unused-argument
            stop_event.set()

        mock_launch_proxy.side_effect = mock_proxy

        # AND a direct (non-proxied) seed fetch that returns the 403 the proxy would have dropped
        seed_response = Response(httpx.Response(403, text="Forbidden"), url="https://example.com/")
        mock_seed_crawler = AsyncMock()
        mock_seed_crawler.async_send.return_value = seed_response
        mock_crawler_cls.with_configuration.return_value.__aenter__.return_value = mock_seed_crawler

        # WHEN exploring
        results = [
            (req, res) async for req, res in explorer.async_explore(deque([Request("https://example.com/")]))
        ]

        # THEN the seed is fetched directly and emitted so host-level modules get their request
        assert len(results) == 1
        assert results[0][0].url == "https://example.com/"
        assert results[0][1].status == 403
        mock_seed_crawler.async_send.assert_awaited_once()
        mock_launch_headless.assert_called_once()

    @patch("wapitiCore.net.intercepting_explorer.AsyncCrawler")
    @patch("wapitiCore.net.intercepting_explorer.launch_proxy")
    @patch("wapitiCore.net.intercepting_explorer.launch_headless_explorer")
    @pytest.mark.asyncio
    async def test_seed_fallback_skips_covered_host(
        self, mock_launch_headless, mock_launch_proxy, mock_crawler_cls
    ):
        # GIVEN a headless crawl that already captured the index (200 html) for the host
        stop_event = asyncio.Event()
        crawler_config = CrawlerConfiguration(Request("https://example.com/"))
        scope = Scope(Request("https://example.com/"), "folder")
        explorer = InterceptingExplorer(crawler_config, scope, stop_event, headless="hidden")

        async def mock_proxy(*args, **kwargs):  # pylint: disable=unused-argument
            queue = args[1]
            request = Request("https://example.com/")
            response = Response(httpx.Response(200, text="<html></html>"), url="https://example.com/")
            await queue.put((request, response))
            stop_event.set()

        mock_launch_proxy.side_effect = mock_proxy

        mock_seed_crawler = AsyncMock()
        mock_crawler_cls.with_configuration.return_value.__aenter__.return_value = mock_seed_crawler

        # WHEN exploring
        results = [
            (req, res) async for req, res in explorer.async_explore(deque([Request("https://example.com/")]))
        ]

        # THEN the host is already covered: no direct fetch, no duplicate
        assert len(results) == 1
        assert results[0][1].status == 200
        mock_seed_crawler.async_send.assert_not_awaited()
        mock_launch_headless.assert_called_once()

    @patch("wapitiCore.net.intercepting_explorer.AsyncCrawler")
    @patch("wapitiCore.net.intercepting_explorer.launch_proxy")
    @patch("wapitiCore.net.intercepting_explorer.launch_headless_explorer")
    @pytest.mark.asyncio
    async def test_seed_fallback_disabled_in_both_mode(
        self, mock_launch_headless, mock_launch_proxy, mock_crawler_cls
    ):
        # GIVEN an explorer with the seed fallback disabled (as done in --headless both, where a
        # standard Explorer already seeded every host into the persister)
        stop_event = asyncio.Event()
        crawler_config = CrawlerConfiguration(Request("https://example.com/"))
        scope = Scope(Request("https://example.com/"), "folder")
        explorer = InterceptingExplorer(
            crawler_config, scope, stop_event, headless="hidden", seed_fallback=False
        )

        async def mock_proxy(*args, **kwargs):  # pylint: disable=unused-argument
            stop_event.set()

        mock_launch_proxy.side_effect = mock_proxy

        mock_seed_crawler = AsyncMock()
        mock_crawler_cls.with_configuration.return_value.__aenter__.return_value = mock_seed_crawler

        # WHEN exploring an uncovered host
        results = [
            (req, res) async for req, res in explorer.async_explore(deque([Request("https://example.com/")]))
        ]

        # THEN no fallback fetch happens: the standard crawler already covered the host
        assert results == []
        mock_seed_crawler.async_send.assert_not_awaited()
        mock_launch_headless.assert_called_once()

    @patch("wapitiCore.net.intercepting_explorer.AsyncCrawler")
    @patch("wapitiCore.net.intercepting_explorer.launch_proxy")
    @patch("wapitiCore.net.intercepting_explorer.launch_headless_explorer")
    @pytest.mark.asyncio
    async def test_seed_fallback_honors_exclusions(
        self, mock_launch_headless, mock_launch_proxy, mock_crawler_cls
    ):
        # GIVEN a headless crawl that captures nothing for the host
        stop_event = asyncio.Event()
        crawler_config = CrawlerConfiguration(Request("https://example.com/"))
        scope = Scope(Request("https://example.com/"), "folder")
        explorer = InterceptingExplorer(crawler_config, scope, stop_event, headless="hidden")

        async def mock_proxy(*args, **kwargs):  # pylint: disable=unused-argument
            stop_event.set()

        mock_launch_proxy.side_effect = mock_proxy

        mock_seed_crawler = AsyncMock()
        mock_crawler_cls.with_configuration.return_value.__aenter__.return_value = mock_seed_crawler

        # WHEN the seed URL matches an exclusion pattern
        results = [
            (req, res) async for req, res in explorer.async_explore(
                deque([Request("https://example.com/")]),
                excluded_urls=["https://example.com/*"],
            )
        ]

        # THEN the fallback skips it instead of fetching it directly
        assert results == []
        mock_seed_crawler.async_send.assert_not_awaited()
        mock_launch_headless.assert_called_once()
