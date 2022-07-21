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
from collections import deque
from typing import Tuple, List, AsyncIterator, Dict, Optional
import logging
from http.cookiejar import Cookie, CookieJar

from mitmproxy import addons
from mitmproxy.master import Master
from mitmproxy.options import Options
from mitmproxy.http import Request as MitmRequest
import httpx
from arsenic import get_session, browsers, services
import structlog

from wapitiCore.net import Request
from wapitiCore.net.response import Response
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.net.crawler_configuration import CrawlerConfiguration
from wapitiCore.net.async_stickycookie import AsyncStickyCookie
from wapitiCore.net.explorer import Explorer
from wapitiCore.net.scope import Scope
from wapitiCore.main.log import log_verbose, log_blue
from wapitiCore.parsers.html import Html


GECKODRIVER = "/home/sirius/bin/geckodriver"


def set_arsenic_log_level(level: int = logging.WARNING):
    # Create logger
    logger = logging.getLogger('arsenic')

    # We need factory, to return application-wide logger
    def logger_factory():
        return logger

    structlog.configure(logger_factory=logger_factory)
    logger.setLevel(level)


set_arsenic_log_level(logging.ERROR)


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
        if self._drop_cookies:
            if "set-cookie" in flow.response.headers:
                del flow.response.headers["set-cookie"]

        content_type = flow.response.headers.get("Content-Type", "text/plain")
        flow.response.stream = False
        # TODO: discard on status code too
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
        proxy: Optional[str] = None,
        drop_cookies: bool = False
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
    master.addons.add(AsyncStickyCookie())
    # Finally here is our custom addon that will generate Wapiti Request and Response objects and push them to the queue
    master.addons.add(MitmFlowToWapitiRequests(data_queue, headers, drop_cookies))
    try:
        await master.run()
    except asyncio.CancelledError:
        print("Stopping mitmproxy")
    return master.addons.get("asyncstickycookie").jar


def mitm_jar_to_cookiejar(cookies: dict) -> CookieJar:
    cookie_jar = CookieJar()
    for scope in cookies:
        hostname: str
        port: int
        path: str

        hostname, port, path = scope
        for key, value in cookies[scope].items():
            print(scope, key, value)
            cookie = Cookie(
                version=0,
                name=key,
                value=value,
                port=str(port),
                port_specified=False,
                domain=hostname if hostname.startswith(".") else "." + hostname,
                domain_specified=True,
                domain_initial_dot=False,
                path=path,
                path_specified=True,
                secure=True,
                expires=None,
                discard=True,
                comment=None,
                comment_url=None,
                rest={'HttpOnly': None},
                rfc2109=False
            )
            cookie_jar.set_cookie(cookie)
    return cookie_jar


async def launch_headless_explorer(
        stop_event: asyncio.Event,
        crawler: AsyncCrawler,
        to_explore: deque,
        scope: Scope,
        proxy_port: int,
        excluded_urls: list = None
):
    stop_event = stop_event
    crawler = crawler
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
        # **{
        #     "moz:firefoxOptions": {
        #         "prefs": {"security.cert_pinning.enforcement_level": 0},
        #         # "args": ["-headless"]
        #     }
        # }
    )
    try:
        async with get_session(service, browser) as headless_client:
            while to_explore:
                request = to_explore.popleft()
                excluded_urls.append(request)
                if request.method == "GET":
                    try:
                        print(f"Fetching {request.url}")
                        await headless_client.get(request.url, timeout=5)
                    except Exception:
                        continue

                    await asyncio.sleep(.1)
                    page_source = await headless_client.get_page_source()
                else:
                    try:
                        response = await crawler.async_send(request)
                    except Exception as exception:
                        print(exception)
                        continue

                    page_source = response.content

                html = Html(page_source, request.url, allow_fragments=True)

                for link in html.links:
                    if not scope.check(link):
                        continue

                    next_request = Request(link)
                    if next_request not in to_explore and next_request not in excluded_urls:
                        to_explore.append(next_request)

                for form in html.iter_forms():
                    if scope.check(form) and form not in to_explore and form not in excluded_urls:
                        to_explore.append(form)
    except:
        pass

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
            headless: bool = False,
    ):
        super().__init__(crawler_configuration, scope, stop_event, parallelism)
        self._mitm_port = mitm_port
        self._proxy = proxy
        self._drop_cookies = drop_cookies
        self._headless = headless
        self._cookies = None

    async def async_explore(
            self,
            to_explore: deque,
            excluded_urls: list = None
    ) -> AsyncIterator[Tuple[Request, Response]]:
        queue = asyncio.Queue()

        # Launch proxy as asyncio task
        mitm_task = asyncio.create_task(
            launch_proxy(
                self._mitm_port,
                queue,
                self._crawler.headers,
                proxy=self._proxy,
                drop_cookies=self._drop_cookies
            )
        )

        headless_task = None
        if self._headless:
            headless_task = asyncio.create_task(
                launch_headless_explorer(
                    self._stopped,
                    self._crawler,
                    to_explore,
                    scope=self._scope,
                    proxy_port=self._mitm_port,
                    excluded_urls=excluded_urls,
                )
            )
        else:
            # We don't use to_explore here, clear it.
            to_explore.clear()

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
                if self._scope.check(request) and request not in self._processed_requests:
                    yield request, response
                    self._processed_requests.append(request)
                    log_verbose(f"[+] {request}")

            if self._stopped.is_set():
                break

        print("Joining queue")
        await queue.join()
        print("Join done")
        if headless_task:
            headless_task.cancel()
            await headless_task
            print("Stopped headless browser")

        mitm_task.cancel()
        self._cookies = await mitm_task
        print("mitm task done")
        await self._crawler.close()

    @property
    def cookie_jar(self):
        return mitm_jar_to_cookiejar(self._cookies)
