#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2023-2026 Nicolas SURRIBAS
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
import os
import re
import sys
from dataclasses import replace
from traceback import print_tb
from typing import Tuple, List, AsyncIterator, Optional, Deque
from logging import getLogger, WARNING, CRITICAL
from http.cookiejar import CookieJar
import inspect
import json

import httpx2
# pylint: disable=protected-access
from playwright._impl._errors import TargetClosedError
from playwright.async_api import async_playwright, Error as PlaywrightError

from wapitiCore.net import Request
from wapitiCore.net.web import urlparse
from wapitiCore.net.cookies import mitm_jar_to_cookiejar
from wapitiCore.net.response import Response
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net.async_stickycookie import AsyncStickyCookie
from wapitiCore.net.proxy import CertificateAuthority, Flow, InterceptingProxy, ProxyRequest
from wapitiCore.net.proxy.server import EVENT_STREAM
from wapitiCore.net.sql_persister import SqlPersister
from wapitiCore.net.explorer import Explorer, EXCLUDED_MEDIA_EXTENSIONS
from wapitiCore.net.scope import Scope, wildcard_translate
from wapitiCore.main.log import log_verbose, log_blue, log_red, logging
from wapitiCore.parsers.html_parser import Html

# Mime types that a browser will commonly display instead of downloading
KNOWN_INTERPRETED_TYPES = (
    "text/plain", "text/html", "application/javascript", "text/javascript", "text/css", "application/json",
    "application/x-javascript", "image/webp", "application/manifest+json", "application/json+protobuf",
    "image/avif", "image/png", "image/gif", "image/x-icon", "font/woff2", "image/jpeg", "image/svg+xml",
    "application/ld+json", "font/ttf", "font/woff", "application/xhtml+xml",
)


# Directory of the certificate authority of the intercepting proxy, inside the configuration directory
CA_DIRECTORY_NAME = "ca"


def is_interpreted_type(mime_type: str) -> bool:
    for known_mime_type in KNOWN_INTERPRETED_TYPES:
        if mime_type.startswith(known_mime_type):
            return True
    return False


def set_playwright_log_level(level: int = WARNING):
    # Create logger
    logger = getLogger('playwright')
    logger.setLevel(level)


set_playwright_log_level(CRITICAL)


def mitm_to_wapiti_request(proxy_request: ProxyRequest) -> Optional[Request]:
    post_params = []
    file_params = []
    enctype = ""
    media_type = proxy_request.media_type

    if media_type == "application/x-www-form-urlencoded":
        post_params.extend(proxy_request.urlencoded_form)
    elif media_type == "multipart/form-data":
        enctype = "multipart/form-data"
        fields, files = proxy_request.multipart_form
        post_params.extend(fields)
        file_params.extend([name, file_value] for name, file_value in files)

    if not enctype and proxy_request.method in ["POST", "PUT", "PATCH"]:
        enctype = proxy_request.headers.get("Content-Type", "")

    if media_type == "application/json":
        try:
            json.loads(proxy_request.text)
        except json.JSONDecodeError:
            # Ignore request if JSON data seems invalid
            return None

    if proxy_request.content and media_type not in ("application/x-www-form-urlencoded", "multipart/form-data"):
        # Not a form: the body (JSON, XML...) is kept as is
        post_params = proxy_request.text

    return Request(
        path=proxy_request.url,
        method=proxy_request.method,
        referer=proxy_request.headers.get("Referer", ""),
        post_params=post_params or None,
        file_params=file_params or None,
        enctype=enctype,
        headers=httpx2.Headers(proxy_request.headers.multi_items()),
    )


class MitmFlowToWapitiRequests:
    """Addon of the intercepting proxy turning what the browser does into Wapiti requests and responses."""

    def __init__(self, data_queue: asyncio.Queue, headers: httpx2.Headers, scope: Scope, drop_cookies: bool = False):
        self._queue = data_queue
        self._headers = headers
        self._drop_cookies = drop_cookies
        self._scope = scope

    async def request(self, flow: Flow):
        for key, value in self._headers.items():
            # This will use our user-agent too.
            # Accept-Encoding is among those headers, so the browser can't ask for a compression we don't know.
            flow.request.headers[key] = value

    async def response(self, flow: Flow):
        response = flow.response
        # 101 is a switch to another protocol (WebSocket): there is no HTTP response to look at.
        # 4xx are certainly broken links, and we don't want to deal with that.
        if response.status_code == 101 or 400 <= response.status_code < 500:
            return

        if self._drop_cookies:
            if "set-cookie" in response.headers:
                del response.headers["set-cookie"]

        content_type = response.headers.get("Content-Type", "text/plain").split(";")[0]
        if content_type.strip().lower() == EVENT_STREAM:
            # Server-sent events: an endless response the page is waiting for, we have nothing to do with it
            return

        # We only need this for the automated part, a human without the headless crawler will be able to deal
        # with download popups. Let's keep in mind we should tweak that later.
        is_forced_download = response.headers.get("content-disposition", "").startswith("attachment")
        if not is_interpreted_type(content_type) or is_forced_download:
            response.status_code = 200
            response.replace_body(b"Lasciate ogne speranza, voi ch'intrate.", "text/plain")
            response.headers.pop("content-disposition", None)
            return

        redirection = response.headers.get("location", "")
        if redirection.startswith(("http://", "https://")) and not self._scope.check(redirection):
            response.status_code = 200
            response.replace_body(b"Lasciate ogne speranza, voi ch'intrate.", "text/plain")
            return

        if response.streamed:
            # The body is too big to be kept by the proxy, the browser gets it but we can't analyze it
            return

        if "text" in content_type or "json" in content_type or "html" in content_type or "xml" in content_type:
            request = mitm_to_wapiti_request(flow.request)
            if request is None:
                return

            wapiti_response = Response(
                httpx2.Response(
                    status_code=response.status_code,
                    headers=response.headers.multi_items(),
                    # httpx2 expect the raw content (not decompressed)
                    content=response.content,
                ),
                url=flow.request.url
            )

            await self._queue.put(
                (request, wapiti_response)
            )


def get_certificate_authority() -> CertificateAuthority:
    """Returns the certificate authority of the intercepting proxy, kept in the configuration directory."""
    return CertificateAuthority(os.path.join(SqlPersister.CONFIG_DIR, CA_DIRECTORY_NAME))


# pylint: disable=too-many-positional-arguments
async def launch_proxy(
        port: int,
        data_queue: asyncio.Queue,
        headers: httpx2.Headers,
        cookies: CookieJar,
        scope: Scope,
        proxy: Optional[str] = None,
        drop_cookies: bool = False,
        intercept_everything: bool = True,
        stop_event: Optional[asyncio.Event] = None,
):
    """
    Run the intercepting proxy until the task is cancelled, then returns the cookies it has seen.

    `intercept_everything` must be False when a human drives the browser: the proxy then only decrypts the
    traffic of the hosts in the scope and leaves the rest of the browsing alone.
    """
    if proxy:
        log_blue(f"Using upstream proxy {proxy}")

    # If ever we want to have both the interception proxy and an automated crawler then we need to sync cookies
    # This addon will do that and also load init cookies in the internal jar
    sticky_cookies = AsyncStickyCookie(cookies)
    try:
        intercepting_proxy = InterceptingProxy(
            get_certificate_authority(),
            port=port,
            addons=[
                sticky_cookies,
                # Our custom addon that will generate Wapiti Request and Response objects and push them to the queue
                MitmFlowToWapitiRequests(data_queue, headers, scope, drop_cookies),
            ],
            upstream_proxy=proxy,
            should_intercept=None if intercept_everything else (lambda host, port: scope.check_host(host)),
        )
        await intercepting_proxy.start()
    except (OSError, ValueError) as exception:
        log_red(f"Can't start the intercepting proxy on port {port}: {exception}")
        if stop_event:
            # Nothing will ever be captured, no need to wait
            stop_event.set()
        return sticky_cookies.jar

    try:
        # Sleep until someone cancels us
        await asyncio.Event().wait()
    except asyncio.CancelledError:
        log_blue("Stopping the intercepting proxy")
    finally:
        await intercepting_proxy.stop()

    return sticky_cookies.jar


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
        for form_request in form.to_requests():
            # if scope.check(form) and form not in to_explore and form not in excluded_requests:
            form_request.link_depth = request.link_depth + 1
            yield form_request


MAX_BUTTONS_PER_PAGE = 10


async def click_in_webpage(page, request: Request, wait_time: float, timeout: float):
    # We are using XPath because CSS selectors doesn't allow to combine nth-of-type with other cool stuff
    total_clicked = 0
    for xpath_selector in (".//button", ".//*[@role=\"button\" and not(@href)]"):
        if total_clicked >= MAX_BUTTONS_PER_PAGE:
            break

        try:
            buttons = await page.query_selector_all(xpath_selector)
        except PlaywrightError:
            continue

        for button in buttons:
            if total_clicked >= MAX_BUTTONS_PER_PAGE:
                break

            try:
                await button.click(timeout=timeout * 1000)
            except PlaywrightError:
                continue
            else:
                total_clicked += 1
                # Use networkidle with a short timeout instead of a fixed delay
                try:
                    await page.wait_for_load_state("networkidle", timeout=wait_time * 1000)
                except PlaywrightError:
                    pass
                if page.url != request.url_with_fragment:
                    await page.goto(
                        request.url_with_fragment,
                        timeout=timeout * 1000,
                        wait_until="domcontentloaded"
                    )


# pylint: disable=too-many-positional-arguments
async def launch_headless_explorer(
        stop_event: asyncio.Event,
        crawler: AsyncCrawler,
        to_explore: Deque[Request],
        scope: Scope,
        proxy_port: int,
        excluded_requests: set,
        exclusion_regexes: List[re.Pattern],
        visibility: str = "hidden",
        wait_time: float = 2.,
        max_depth: int = 20,
):
    # The headless browser will be configured to use the MITM proxy
    # The intercepting will be in charge of generating Request objects.
    # This is the only way as a headless browser can't provide us response headers.
    proxy_settings = {
        "server": f"http://127.0.0.1:{proxy_port}"
    }

    # We need to make a copy of this set otherwise requests won't make their way into async_explore (because set is
    # shared). Also, we want our own set here because we will see URLs with anchors that the proxy can't catch.
    excluded_requests = set(excluded_requests)

    try:
        async with async_playwright() as p:
            browser = await p.firefox.launch(
                headless=visibility == "hidden",
                proxy=proxy_settings,
                firefox_user_prefs={
                    "network.proxy.allow_hijacking_localhost": True,
                    "devtools.jsonview.enabled": False,
                }
            )
            context = await browser.new_context(ignore_https_errors=True)
            page = await context.new_page()

            # Shadow set for O(1) lookups on to_explore deque
            to_explore_set = set(to_explore)

            try:
                while to_explore and not stop_event.is_set():
                    request = to_explore.popleft()
                    to_explore_set.discard(request)
                    excluded_requests.add(request)

                    if request.method == "GET":
                        try:
                            await page.goto(
                                request.url_with_fragment,
                                timeout=crawler.timeout.connect * 1000,
                                wait_until="domcontentloaded"
                            )
                            # Wait for network idle with a short timeout instead of a fixed delay.
                            # This adapts to the actual page load speed: fast pages proceed quickly,
                            # heavy pages wait only as long as needed.
                            try:
                                await page.wait_for_load_state(
                                    "networkidle",
                                    timeout=wait_time * 1000
                                )
                            except PlaywrightError:
                                # Timeout reached, proceed anyway — we've waited long enough
                                pass
                            # We may be redirected outside our target so let's check the URL first
                            if not scope.check(page.url):
                                continue

                            page_source = await page.content()
                            await click_in_webpage(page, request, wait_time, timeout=crawler.timeout.connect)
                        except (PlaywrightError, asyncio.TimeoutError) as exception:
                            if isinstance(exception, TargetClosedError):
                                break

                            logging.error("%s generated an exception: %s", request, type(exception).__name__)
                            continue
                    else:
                        try:
                            response = await crawler.async_send(request, timeout=crawler.timeout.connect)
                        except httpx2.RequestError as exception:
                            logging.error("%s generated an exception: %s", request, type(exception).__name__)
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

                        if next_request not in to_explore_set and next_request not in excluded_requests:
                            to_explore.append(next_request)
                            to_explore_set.add(next_request)
            finally:
                await browser.close()

    except Exception as exception:  # pylint: disable=broad-except
        if isinstance(exception, TargetClosedError):
            return

        exception_traceback = sys.exc_info()[2]
        print_tb(exception_traceback)
        frm = inspect.trace()[-1]
        mod = inspect.getmodule(frm[0])
        logging.error(
            "Headless browser stopped prematurely due to exception: %s.%s", mod.__name__, type(exception).__name__
        )

    await asyncio.sleep(1)
    stop_event.set()


class InterceptingExplorer(Explorer):
    # pylint: disable=too-many-positional-arguments
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
            wait_time: float = 2.,
            seed_fallback: bool = True
    ):
        super().__init__(crawler_configuration, scope, stop_event, parallelism)
        # Kept so the seed fallback can build a crawler that bypasses the MITM proxy
        self._crawler_configuration = crawler_configuration
        self._mitm_port = mitm_port
        self._proxy = proxy
        self._drop_cookies = drop_cookies
        self._headless = headless
        # Whether to directly fetch uncovered seeds after the headless crawl. Disabled in
        # "both" mode, where a standard Explorer already seeded every host into the same
        # persister, so a fallback fetch would only re-persist a duplicate.
        self._seed_fallback_enabled = seed_fallback
        self._final_cookies = None
        self._cookies = cookies or CookieJar()
        self._wait_time = wait_time
        self._headless_task = None
        self._mitm_task = None
        self._queue = None

    async def process_requests(self, excluded_requests, exclusion_regexes):
        while True:
            if self._stopped.is_set() and self._queue.empty():
                break

            try:
                request, response = await asyncio.wait_for(self._queue.get(), timeout=0.5)
            except asyncio.TimeoutError:
                continue
            except KeyboardInterrupt:
                break

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

            if self.has_too_many_parameters(request):
                continue

            # Same raw body budget as the standard explorer, applied last so that a request
            # dropped by another rule takes no budget slot: a rejected body is never persisted,
            # never attacked and does not consume a per-directory file slot either.
            if self.has_enough_raw_bodies(request):
                continue

            self._file_counts[dir_name] += 1

            if self._qs_limit and request.parameters_count:
                self._pattern_counts[request.pattern] += 1

            yield request, response
            self._processed_requests.add(request)
            log_verbose(f"[+] {request}")

    async def async_explore(
            self,
            to_explore: Deque[Request],
            excluded_urls: list = None
    ) -> AsyncIterator[Tuple[Request, Response]]:
        self._queue = asyncio.Queue()

        # Snapshot the seeds now: launch_headless_explorer drains the to_explore deque below.
        seed_requests = list(to_explore)

        exclusion_regexes = []
        excluded_requests = set()

        if isinstance(excluded_urls, list):
            for bad_request in excluded_urls:
                if isinstance(bad_request, str):
                    exclusion_regexes.append(wildcard_translate(bad_request))
                elif isinstance(bad_request, Request):
                    excluded_requests.add(bad_request)

        if self._headless == "no":
            authority = get_certificate_authority()
            log_blue(
                f"Launching the intercepting proxy on port {self._mitm_port}. "
                "Configure your browser to use it, press ctrl+c when you are done."
            )
            log_blue(
                "To browse HTTPS websites, import this certificate as a trusted authority in your browser "
                f"(a dedicated browser profile is recommended): {authority.certificate_path}"
            )
            log_blue(f"It can also be downloaded from http://127.0.0.1:{self._mitm_port}/")
        else:
            log_blue(f"Launching the intercepting proxy on port {self._mitm_port} for the headless browser.")

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
                # A human browsing through the proxy visits more than the target, see launch_proxy
                intercept_everything=self._headless != "no",
                stop_event=self._stopped,
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

        # Track which hosts the headless crawl actually produced a request for. We build this
        # ourselves rather than reading self._processed_requests because process_requests marks
        # a request processed only after its yield, and the loop below may break right after the
        # last yield (stop event) before that happens.
        covered_hosts = set()
        async for request, response in self.process_requests(excluded_requests, exclusion_regexes):
            covered_hosts.add(request.hostname)
            yield request, response
            if self._stopped.is_set():
                break

        # The MITM proxy only forwards responses that are not 4xx and whose content-type is
        # text/json/html/xml. A host whose only reachable endpoint is filtered out (e.g. an
        # index returning 403, or a non-text root) would never produce a single request, so
        # host-level modules (ssl, http_headers, ...) that need one request per host would
        # never run against it. Fetch the uncovered seeds directly to restore that coverage.
        # Skipped in "both" mode (see self._seed_fallback_enabled).
        if self._headless != "no" and self._seed_fallback_enabled:
            async for request, response in self._seed_fallback(
                seed_requests, covered_hosts, excluded_requests, exclusion_regexes
            ):
                yield request, response

    async def _seed_fallback(
            self,
            seed_requests: List[Request],
            covered_hosts: set,
            excluded_requests: set,
            exclusion_regexes: List[re.Pattern],
    ) -> AsyncIterator[Tuple[Request, Response]]:
        """
        Directly fetch the seed URLs of hosts the headless crawl did not cover, bypassing the
        MITM proxy filters, so host-level modules always get at least one request per host even
        when the index returns a 4xx or a non-text response. Headless-captured requests, when
        they exist, always take precedence (the host is already in covered_hosts).
        """
        # self._crawler routes through the MITM proxy; use the real upstream proxy (often none).
        seed_configuration = replace(self._crawler_configuration, proxy=self._proxy)
        async with AsyncCrawler.with_configuration(seed_configuration) as seed_crawler:
            for request in seed_requests:
                if request.method != "GET" or request.hostname in covered_hosts:
                    continue

                if not self._scope.check(request):
                    continue

                # Honor the same exclusions process_requests applies to intercepted requests.
                if request in excluded_requests or any(
                    regex.match(request.url) for regex in exclusion_regexes
                ):
                    continue

                try:
                    # follow_redirects=True so the terminal 200 is stored: a bare 3xx to the
                    # trailing-slash variant would be skipped by must_attack as a directory
                    # redirection.
                    response = await seed_crawler.async_send(request, follow_redirects=True)
                except (ConnectionError, httpx2.RequestError) as exception:
                    logging.error("[!] %s while seeding %s", type(exception).__name__, request.url)
                    continue

                covered_hosts.add(request.hostname)
                self._processed_requests.add(request)
                yield request, response

    def empty_queue(self):
        while not self._queue.empty():
            self._queue.get_nowait()
            self._queue.task_done()

    async def clean(self):
        self.empty_queue()

        # The headless crawler must stop when the stop event is set, let's just wait for it
        if self._headless_task:
            await self._headless_task

        self._mitm_task.cancel()
        self._final_cookies = await self._mitm_task
        await self._crawler.close()

    @property
    def cookie_jar(self):
        return mitm_jar_to_cookiejar(self._final_cookies)
