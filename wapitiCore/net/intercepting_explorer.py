#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2023 Nicolas SURRIBAS
# Copyright (C) 2024 Cyberwatch
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
import asyncio
import re
import sys
from traceback import print_tb
from typing import Tuple, List, AsyncIterator, Dict, Optional, Deque
from logging import getLogger, WARNING, CRITICAL
from http.cookiejar import CookieJar
from urllib.parse import urlparse
import inspect
import os
import json

from mitmproxy import addons
from mitmproxy.master import Master
from mitmproxy.options import Options
from mitmproxy.http import Request as MitmRequest
import httpx
from arsenic import get_session, browsers, services
from arsenic.constants import SelectorType
from arsenic.errors import ArsenicError, ElementNotInteractable, UnknownArsenicError, NoSuchElement
import structlog

from wapitiCore.net import Request
from wapitiCore.net.cookies import mitm_jar_to_cookiejar
from wapitiCore.net.response import Response
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net.async_stickycookie import AsyncStickyCookie
from wapitiCore.net.explorer import Explorer, EXCLUDED_MEDIA_EXTENSIONS
from wapitiCore.net.scope import Scope, wildcard_translate
from wapitiCore.main.log import log_verbose, log_blue, logging
from wapitiCore.parsers.html_parser import Html

# Mime types that a browser will commonly display instead of downloading
KNOWN_INTERPRETED_TYPES = (
    "text/plain", "text/html", "application/javascript", "text/javascript", "text/css", "application/json",
    "application/x-javascript", "image/webp", "application/manifest+json", "application/json+protobuf",
    "image/avif", "image/png", "image/gif", "image/x-icon", "font/woff2", "image/jpeg", "image/svg+xml",
    "application/ld+json", "font/ttf", "font/woff", "application/xhtml+xml",
)


def is_interpreted_type(mime_type: str) -> bool:
    for known_mime_type in KNOWN_INTERPRETED_TYPES:
        if mime_type.startswith(known_mime_type):
            return True
    return False


def set_arsenic_log_level(level: int = WARNING):
    # Create logger
    logger = getLogger('arsenic')

    # We need factory, to return application-wide logger
    def logger_factory():
        return logger

    structlog.configure(logger_factory=logger_factory)
    logger.setLevel(level)


set_arsenic_log_level(CRITICAL)


def decode_key_value_dict(bytes_dict: Dict[bytes, bytes], multi: bool = True) -> List[Tuple[str, str]]:
    result = []
    for key, value in bytes_dict.items(multi=multi):
        if isinstance(key, bytes):
            key = key.decode("utf-8", errors="ignore")
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="ignore")
        result.append((key, value))
    return result


def mitm_to_wapiti_request(mitm_request: MitmRequest) -> Optional[Request]:
    post_params = []
    enctype = ""
    if mitm_request.urlencoded_form:
        post_params.extend(decode_key_value_dict(mitm_request.urlencoded_form))

    if mitm_request.multipart_form:
        enctype = "multipart/form-data"
        # This is wrong but mitmproxy doesn't give files entries (along with filename, mime type)
        # so we will consider values as simple fields but still send using multipart encoding
        post_params.extend(decode_key_value_dict(mitm_request.multipart_form))

    if not enctype and mitm_request.method in ["POST", "PUT", "PATCH"]:
        enctype = mitm_request.headers.get("Content-Type", "")

    if enctype == "application/json":
        try:
            json.loads(mitm_request.text)
        except json.JSONDecodeError:
            # Ignore request if JSON data seems invalid
            return None

        post_params = mitm_request.text

    request = Request(
        path=mitm_request.url,
        method=mitm_request.method,
        referer=mitm_request.headers.get("Referer", ""),
        post_params=post_params or None,
        enctype=enctype
    )
    request.set_headers(httpx.Headers(decode_key_value_dict(mitm_request.headers)))
    return request


class MitmFlowToWapitiRequests:
    def __init__(self, data_queue: asyncio.Queue, headers: httpx.Headers, scope: Scope, drop_cookies: bool = False):
        self._queue = data_queue
        self._headers = headers
        self._drop_cookies = drop_cookies
        self._scope = scope

    async def request(self, flow):
        for key, value in self._headers.items():
            # This will use our user-agent too
            flow.request.headers[key] = value

    async def response(self, flow):
        if flow.request.method.upper() == "CONNECT":
            return

        if 400 <= flow.response.status_code < 500:
            # Those are certainly broken links, and we don't want to deal with that
            return

        if self._drop_cookies:
            if "set-cookie" in flow.response.headers:
                del flow.response.headers["set-cookie"]

        content_type = flow.response.headers.get("Content-Type", "text/plain").split(";")[0]
        flow.response.stream = False

        # We only need this for the automated part, a human without the headless crawler will be able to deal
        # with download popups. Let's keep in mind we should tweak that later.
        is_forced_download = flow.response.headers.get("content-disposition", "").startswith("attachment")
        if not is_interpreted_type(content_type) or is_forced_download:
            flow.response.status_code = 200
            flow.response.content = b"Lasciate ogne speranza, voi ch'intrate."
            flow.response.headers["content-type"] = "text/plain"
            flow.response.headers.pop("content-disposition", "")
            return

        redirection = flow.response.headers.get("location", "")
        if redirection.startswith(("http://", "https://")) and not self._scope.check(redirection):
            flow.response.status_code = 200
            flow.response.content = b"Lasciate ogne speranza, voi ch'intrate."
            flow.response.headers["content-type"] = "text/plain"
            return

        if "text" in content_type or "json" in content_type or "html" in content_type or "xml" in content_type:
            request = mitm_to_wapiti_request(flow.request)
            if request is None:
                return

            decoded_headers = decode_key_value_dict(flow.response.headers)

            response = Response(
                httpx.Response(
                    status_code=flow.response.status_code,
                    headers=decoded_headers,
                    # httpx expect the raw content (not decompressed)
                    content=flow.response.raw_content,
                ),
                url=flow.request.url
            )

            await self._queue.put(
                (request, response)
            )


async def launch_proxy(
        port: int,
        data_queue: asyncio.Queue,
        headers: httpx.Headers,
        cookies: CookieJar,
        scope: Scope,
        proxy: Optional[str] = None,
        drop_cookies: bool = False,
):
    log_blue(
        f"Launching MitmProxy on port {port}. Configure your browser to use it, press ctrl+c when you are done."
    )
    opt = Options()
    # We can use an upstream proxy that way but socks is not supported
    if proxy:
        log_blue(f"Using upstream proxy {proxy}")
        opt.update(mode=f"upstream:{proxy}")

    opt.update(listen_port=port,  http2=False, ssl_insecure=True)
    master = Master(opt)
    master.addons.add(addons.core.Core())
    master.addons.add(addons.proxyserver.Proxyserver())
    master.addons.add(addons.next_layer.NextLayer())
    # mitmproxy will generate an authority cert in the ~/.mitmproxy directory. Load it in your browser.
    master.addons.add(addons.tlsconfig.TlsConfig())
    # If ever we want to have both the interception proxy and an automated crawler then we need to sync cookies
    # This mitmproxy module will do that and also load init cookies in the internal jar
    master.addons.add(AsyncStickyCookie(cookies))
    # Finally here is our custom addon that will generate Wapiti Request and Response objects and push them to the queue
    master.addons.add(MitmFlowToWapitiRequests(data_queue, headers, scope, drop_cookies))
    try:
        await master.run()
    except asyncio.CancelledError:
        log_blue("Stopping mitmproxy")
    return master.addons.get("asyncstickycookie").jar


def extract_requests(html: Html, request: Request):
    candidates = html.links + html.js_redirections + html.html_redirections + list(html.extra_urls)

    for link in candidates:
        url_parts = urlparse(link)
        if url_parts.path.endswith((".css", ".js")):
            continue

        if not url_parts.query and url_parts.path.endswith(EXCLUDED_MEDIA_EXTENSIONS):
            continue

        next_request = Request(link, link_depth=request.link_depth + 1)
        yield next_request

        if "?" in link:
            next_request = Request(link.split("?")[0], link_depth=request.link_depth + 1)
            yield next_request

    for form in html.iter_forms():
        # if scope.check(form) and form not in to_explore and form not in excluded_requests:
        form.link_depth = request.link_depth + 1
        yield form


async def click_in_webpage(headless_client, request: Request, wait_time: float, timeout: float):
    # We are using XPath because CSS selectors doesn't allow to combine nth-of-type with other cool stuff
    for xpath_selector in (".//button", ".//*[@role=\"button\" and not(@href)]"):
        button_index = 1
        while True:
            try:
                element = await headless_client.get_element(
                    f"({xpath_selector})[{button_index}]",
                    selector_type=SelectorType.xpath,
                )
                await element.click()
            except (ElementNotInteractable, UnknownArsenicError):
                button_index += 1
                continue
            except NoSuchElement:
                # No more buttons
                break
            else:
                button_index += 1
                await asyncio.sleep(wait_time)
                current_url = await headless_client.get_url()
                if current_url != request.url_with_fragment:
                    await headless_client.get(request.url_with_fragment, timeout=timeout)


async def launch_headless_explorer(
        stop_event: asyncio.Event,
        crawler: AsyncCrawler,
        to_explore: Deque[Request],
        scope: Scope,
        proxy_port: int,
        excluded_requests: List[Request],
        exclusion_regexes: List[re.Pattern],
        visibility: str = "hidden",
        wait_time: float = 2.,
        max_depth: int = 20,
):
    # The headless browser will be configured to use the MITM proxy
    # The intercepting will be in charge of generating Request objects.
    # This is the only way as a headless browser can't provide us response headers.
    proxy_settings = {
        "proxyType": "manual",
        "httpProxy": f"127.0.0.1:{proxy_port}",
        "sslProxy": f"127.0.0.1:{proxy_port}"
    }
    browser = browsers.Firefox(
        proxy=proxy_settings,
        acceptInsecureCerts=True,
        **{
            "moz:firefoxOptions": {
                "prefs": {
                    "network.proxy.allow_hijacking_localhost": True,
                    "devtools.jsonview.enabled": False,
                    # "security.cert_pinning.enforcement_level": 0,
                    # "browser.download.panel.shown": False,  # Unfortunately doesn't seem to work
                    # "browser.download.folderList": 2,
                    # "browser.download.manager.showWhenStarting": False,
                    # "browser.helperApps.neverAsk.saveToDisk": "application/octet-stream",
                },
                "args": ["-headless"] if visibility == "hidden" else []
            }
        }
    )

    # We need to make a copy of this list otherwise requests won't make their way into async_explore (because list is
    # shared). Also, we want our own list here because we will see URLs with anchors that the proxy can't catch.
    excluded_requests = list(excluded_requests)

    try:
        async with get_session(services.Geckodriver(log_file=os.devnull), browser) as headless_client:
            while to_explore and not stop_event.is_set():
                request = to_explore.popleft()
                excluded_requests.append(request)
                request.set_cookies(crawler.cookie_jar)

                if request.method == "GET":
                    try:
                        await headless_client.get(request.url_with_fragment, timeout=crawler.timeout.connect)
                        await asyncio.sleep(wait_time)
                        # We may be redirected outside our target so let's check the URL first
                        if not scope.check(await headless_client.get_url()):
                            continue

                        page_source = await headless_client.get_page_source()
                        await click_in_webpage(headless_client, request, wait_time, timeout=crawler.timeout.connect)
                    except (ArsenicError, asyncio.TimeoutError) as exception:
                        logging.error(f"{request} generated an exception: {exception.__class__.__name__}")
                        continue
                else:
                    try:
                        response = await crawler.async_send(request, timeout=crawler.timeout.connect)
                    except httpx.RequestError as exception:
                        logging.error(f"{request} generated an exception: {exception.__class__.__name__}")
                        continue

                    page_source = response.content

                if request.link_depth == max_depth:
                    continue

                html = Html(page_source, request.url, allow_fragments=True)

                for next_request in extract_requests(html, request):
                    if not scope.check(next_request):
                        continue

                    if any(regex.match(next_request.url) for regex in exclusion_regexes):
                        continue

                    if next_request not in to_explore and next_request not in excluded_requests:
                        to_explore.append(next_request)

    except Exception as exception:  # pylint: disable=broad-except
        exception_traceback = sys.exc_info()[2]
        print_tb(exception_traceback)
        frm = inspect.trace()[-1]
        mod = inspect.getmodule(frm[0])
        logging.error(
            f"Headless browser stopped prematurely due to exception: {mod.__name__}.{exception.__class__.__name__}"
        )

    await asyncio.sleep(1)
    stop_event.set()


class InterceptingExplorer(Explorer):
    def __init__(
            self,
            crawler_configuration: CrawlerConfiguration,
            scope: Scope,
            stop_event: asyncio.Event,
            parallelism: int = 8,
            mitm_port: int = 8080,
            proxy: Optional[str] = None,
            drop_cookies: bool = False,
            headless: str = "no",
            cookies: Optional[CookieJar] = None,
            wait_time: float = 2.
    ):
        super().__init__(crawler_configuration, scope, stop_event, parallelism)
        self._mitm_port = mitm_port
        self._proxy = proxy
        self._drop_cookies = drop_cookies
        self._headless = headless
        self._final_cookies = None
        self._cookies = cookies or CookieJar()
        self._wait_time = wait_time
        self._headless_task = None
        self._mitm_task = None
        self._queue = None

    async def process_requests(self, excluded_requests, exclusion_regexes):
        while True:
            try:
                request, response = self._queue.get_nowait()
            except asyncio.QueueEmpty:
                await asyncio.sleep(.1)
            except KeyboardInterrupt:
                break
            else:
                self._queue.task_done()

                # Scope check and deduplication are made here
                if not self._scope.check(request) or request in self._processed_requests:
                    continue

                # Check for exclusion here because we don't have full control over the headless browser
                if request in excluded_requests or any(regex.match(request.url) for regex in exclusion_regexes):
                    continue

                dir_name = request.dir_name
                if self._max_files_per_dir and self._file_counts[dir_name] >= self._max_files_per_dir:
                    continue

                self._file_counts[dir_name] += 1

                if self.has_too_many_parameters(request):
                    continue

                if self._qs_limit and request.parameters_count:
                    self._pattern_counts[request.pattern] += 1

                yield request, response
                self._processed_requests.append(request)
                log_verbose(f"[+] {request}")

            if self._stopped.is_set():
                break

    async def async_explore(
            self,
            to_explore: Deque[Request],
            excluded_urls: list = None
    ) -> AsyncIterator[Tuple[Request, Response]]:
        self._queue = asyncio.Queue()

        exclusion_regexes = []
        excluded_requests = []

        if isinstance(excluded_urls, list):
            for bad_request in excluded_urls:
                if isinstance(bad_request, str):
                    exclusion_regexes.append(wildcard_translate(bad_request))
                elif isinstance(bad_request, Request):
                    excluded_requests.append(bad_request)

        # Launch proxy as asyncio task
        self._mitm_task = asyncio.create_task(
            launch_proxy(
                self._mitm_port,
                self._queue,
                self._crawler.headers,
                self._cookies,
                self._scope,
                proxy=self._proxy,
                drop_cookies=self._drop_cookies,
            )
        )

        if self._headless == "no":
            # No headless crawler, just intercepting mode so no starting URLs
            to_explore.clear()
        else:
            self._headless_task = asyncio.create_task(
                launch_headless_explorer(
                    self._stopped,
                    self._crawler,
                    to_explore,
                    scope=self._scope,
                    proxy_port=self._mitm_port,
                    excluded_requests=excluded_requests,
                    exclusion_regexes=exclusion_regexes,
                    visibility=self._headless,
                    wait_time=self._wait_time,
                    max_depth=self._max_depth,
                )
            )

        async for request, response in self.process_requests(excluded_requests, exclusion_regexes):
            yield request, response
            if self._stopped.is_set():
                break

    def empty_queue(self):
        while not self._queue.empty():
            self._queue.get_nowait()
            self._queue.task_done()

    async def clean(self):
        self.empty_queue()

        # The headless crawler must stop when the stop event is set, let's just wait for it
        if self._headless_task:
            await self._headless_task

        # We are canceling the mitm proxy, but we could have used a special request to shut down the master to.
        # https://docs.mitmproxy.org/stable/addons-examples/#shutdown
        self._mitm_task.cancel()
        self._final_cookies = await self._mitm_task
        await self._crawler.close()

    @property
    def cookie_jar(self):
        return mitm_jar_to_cookiejar(self._final_cookies)
