#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2022 Nicolas SURRIBAS
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
from typing import Tuple, List, AsyncIterator, Dict, Optional, Deque
from logging import getLogger, WARNING, ERROR
from http.cookiejar import CookieJar
from urllib.parse import urlparse

from mitmproxy import addons
from mitmproxy.master import Master
from mitmproxy.options import Options
from mitmproxy.http import Request as MitmRequest
import httpx
from arsenic import get_session, browsers, services
from arsenic.errors import ArsenicError
import structlog

from wapitiCore.net import Request
from wapitiCore.net.cookies import mitm_jar_to_cookiejar
from wapitiCore.net.response import Response
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.net.crawler_configuration import CrawlerConfiguration
from wapitiCore.net.async_stickycookie import AsyncStickyCookie
from wapitiCore.net.explorer import Explorer, EXCLUDED_MEDIA_EXTENSIONS, wildcard_translate
from wapitiCore.net.scope import Scope
from wapitiCore.main.log import log_verbose, log_blue, logging
from wapitiCore.parsers.html import Html


def set_arsenic_log_level(level: int = WARNING):
    # Create logger
    logger = getLogger('arsenic')

    # We need factory, to return application-wide logger
    def logger_factory():
        return logger

    structlog.configure(logger_factory=logger_factory)
    logger.setLevel(level)


set_arsenic_log_level(ERROR)


def decode_key_value_dict(bytes_dict: Dict[bytes, bytes], multi: bool = True) -> List[Tuple[str, str]]:
    result = []
    for key, value in bytes_dict.items(multi=multi):
        if isinstance(key, bytes):
            key = key.decode("utf-8", errors="ignore")
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="ignore")
        result.append((key, value))
    return result


def mitm_to_wapiti_request(mitm_request: MitmRequest) -> Request:
    post_params = []
    enctype = ""
    if mitm_request.urlencoded_form:
        post_params.extend(decode_key_value_dict(mitm_request.urlencoded_form))

    if mitm_request.multipart_form:
        enctype = "multipart/form-data"
        # This is wrong but mitmproxy doesn't give files entries (along with filename, mime type)
        # so we will consider values as simple fields but still send using multipart encoding
        post_params.extend(decode_key_value_dict(mitm_request.multipart_form))

    if not enctype and mitm_request.method == "POST":
        enctype = mitm_request.headers.get("Content-Type", "")

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
    def __init__(self, data_queue: asyncio.Queue, headers: httpx.Headers, drop_cookies: bool = False):
        self._queue = data_queue
        self._headers = headers
        self._drop_cookies = drop_cookies

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

        content_type = flow.response.headers.get("Content-Type", "text/plain")
        flow.response.stream = False

        if "text" in content_type or "json" in content_type:
            request = mitm_to_wapiti_request(flow.request)

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

    opt.update(listen_port=port,  http2=False)
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
    master.addons.add(MitmFlowToWapitiRequests(data_queue, headers, drop_cookies))
    try:
        await master.run()
    except asyncio.CancelledError:
        log_blue("Stopping mitmproxy")
    return master.addons.get("asyncstickycookie").jar


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
    proxy = f"127.0.0.1:{proxy_port}"
    proxy_settings = {
        "proxyType": "manual",
        "httpProxy": proxy,
        "sslProxy": proxy
    }
    service = services.Geckodriver()
    browser = browsers.Firefox(
        proxy=proxy_settings,
        acceptInsecureCerts=True,
        **{
            "moz:firefoxOptions": {
                # "prefs": {
                #     "security.cert_pinning.enforcement_level": 0,
                #     "browser.download.panel.shown": False,  # Unfortunately doesn't seem to work
                # },
                "args": ["-headless"] if visibility == "hidden" else []
            }
        }
    )

    # We need to make a copy of this list otherwise requests won't make their way into async_explore (because list is
    # shared). Also, we want our own list here because we will see URLs with anchors that the proxy can't catch.
    excluded_requests = list(excluded_requests)

    try:
        async with get_session(service, browser) as headless_client:
            while to_explore and not stop_event.is_set():
                request = to_explore.popleft()
                excluded_requests.append(request)

                if request.method == "GET":
                    try:
                        await headless_client.get(request.url_with_fragment, timeout=5)
                        await asyncio.sleep(wait_time)
                        # We may be redirected outside our target so let's check the URL first
                        if not scope.check(await headless_client.get_url()):
                            continue

                        page_source = await headless_client.get_page_source()
                    except ArsenicError as exception:
                        logging.error(f"{request} generated an exception: {exception.__class__.__name__}")
                        continue
                else:
                    try:
                        response = await crawler.async_send(request)
                    except httpx.RequestError as exception:
                        logging.error(f"{request} generated an exception: {exception.__class__.__name__}")
                        continue

                    page_source = response.content

                if request.link_depth == max_depth:
                    continue

                html = Html(page_source, request.url, allow_fragments=True)
                candidates = html.links + html.js_redirections + html.html_redirections + list(html.extra_urls)

                for link in candidates:
                    if not scope.check(link):
                        continue

                    url_parts = urlparse(link)
                    if url_parts.path.endswith((".css", ".js")):
                        continue

                    if not url_parts.query and url_parts.path.endswith(EXCLUDED_MEDIA_EXTENSIONS):
                        continue

                    if any(regex.match(link) for regex in exclusion_regexes):
                        continue

                    next_request = Request(link, link_depth=request.link_depth + 1)
                    if next_request not in to_explore and next_request not in excluded_requests:
                        to_explore.append(next_request)

                    if "?" in link:
                        next_request = Request(link.split("?")[0], link_depth=request.link_depth + 1)
                        if next_request not in to_explore and next_request not in excluded_requests:
                            to_explore.append(next_request)

                for form in html.iter_forms():
                    if scope.check(form) and form not in to_explore and form not in excluded_requests:
                        form.link_depth = request.link_depth + 1
                        to_explore.append(form)

    except Exception as exception:  # pylint: disable=broad-except
        logging.error(f"Headless browser stopped prematurely due to exception: {exception.__class__.__name__}")

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

    async def async_explore(
            self,
            to_explore: Deque[Request],
            excluded_urls: list = None
    ) -> AsyncIterator[Tuple[Request, Response]]:
        queue = asyncio.Queue()

        exclusion_regexes = []
        excluded_requests = []

        if isinstance(excluded_urls, list):
            while True:
                try:
                    bad_request = excluded_urls.pop()
                except IndexError:
                    break
                else:
                    if isinstance(bad_request, str):
                        exclusion_regexes.append(wildcard_translate(bad_request))
                    elif isinstance(bad_request, Request):
                        excluded_requests.append(bad_request)

        # Launch proxy as asyncio task
        mitm_task = asyncio.create_task(
            launch_proxy(
                self._mitm_port,
                queue,
                self._crawler.headers,
                proxy=self._proxy,
                drop_cookies=self._drop_cookies,
                cookies=self._cookies,
            )
        )

        headless_task = None
        if self._headless == "no":
            # No headless crawler, just intercepting mode so no starting URLs
            to_explore.clear()
        else:
            headless_task = asyncio.create_task(
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

        while True:
            try:
                request, response = queue.get_nowait()
            except asyncio.QueueEmpty:
                await asyncio.sleep(.1)
            except KeyboardInterrupt:
                break
            else:
                queue.task_done()

                # Scope check and deduplication are made here
                if not self._scope.check(request) or request in self._processed_requests:
                    continue

                # Check for exclusion here because we don't have full control over the headless browser
                if request in excluded_requests or any(regex.match(request.url) for regex in exclusion_regexes):
                    continue

                yield request, response
                self._processed_requests.append(request)
                log_verbose(f"[+] {request}")

            if self._stopped.is_set():
                break

        await queue.join()
        # The headless crawler must stop when the stop event is set, let's just wait for it
        if headless_task:
            await headless_task

        # We are canceling the mitm proxy, but we could have used a special request to shut down the master to.
        # https://docs.mitmproxy.org/stable/addons-examples/#shutdown
        mitm_task.cancel()
        self._final_cookies = await mitm_task
        await self._crawler.close()

    @property
    def cookie_jar(self):
        return mitm_jar_to_cookiejar(self._final_cookies)
