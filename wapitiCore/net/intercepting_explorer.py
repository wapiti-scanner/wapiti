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
from typing import Tuple, List, AsyncIterator, Dict

from mitmproxy import addons
from mitmproxy.master import Master
from mitmproxy.options import Options
from mitmproxy.http import Request as MitmRequest
import httpx

from wapitiCore.net.web import Request
from wapitiCore.net.response import Response
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.net.async_stickycookie import AsyncStickyCookie
from wapitiCore.net.explorer import Explorer
from wapitiCore.net.scope import Scope
from wapitiCore.main.log import log_verbose


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
    request.set_sent_headers(httpx.Headers(decode_key_value_dict(mitm_request.headers)))
    return request


class MitmFlowToWapitiRequests:
    def __init__(self, data_queue: asyncio.Queue, user_agent: str):
        self._queue = data_queue
        self._user_agent = user_agent

    async def request(self, flow):
        # Let's overwrite the user-agent so every client using the proxy will share the same value
        flow.request.headers["User-Agent"] = self._user_agent

    async def response(self, flow):
        content_type = flow.response.headers.get("Content-Type", "text/plain")
        flow.response.stream = False
        if "text" in content_type or "json" in content_type:
            request = mitm_to_wapiti_request(flow.request)
            request.status = flow.response.status_code
            request.set_headers(httpx.Headers(decode_key_value_dict(flow.response.headers)))

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


async def launch_proxy(port: int, data_queue: asyncio.Queue, user_agent: str):
    opt = Options()
    # We can use an upstream proxy that way but socks is not supported
    # opt.update(mode="upstream:http://127.0.0.1:8888/")
    opt.update(listen_port=port)
    master = Master(opt)
    master.addons.add(addons.core.Core())
    master.addons.add(addons.proxyserver.Proxyserver())
    master.addons.add(addons.next_layer.NextLayer())
    # mitmproxy will generate an authority cert in the ~/.mitmproxy directory. Load it in your browser.
    master.addons.add(addons.tlsconfig.TlsConfig())
    # If ever we want to have both the interception proxy and an automated crawler then we need to sync cookies
    master.addons.add(AsyncStickyCookie())
    # Finally here is our custom addon that will generate Wapiti Request and Response objects and push them to the queue
    master.addons.add(MitmFlowToWapitiRequests(data_queue, user_agent))
    print(f"Launching MitmProxy on port {port}. Configure your browser to use it, press ctrl+c when you are done.")
    await master.run()


class InterceptingExplorer(Explorer):
    def __init__(
            self,
            # At the moment this is ugly, but we may really have a crawler there later.
            # However, the Explorer may later become the class creating the crawler object...
            # not sure how to sync with the attack step then.
            crawler_instance: AsyncCrawler,
            scope: Scope,
            stop_event: asyncio.Event,
            parallelism: int = 8,
            mitm_port: int = 8080
    ):
        super().__init__(crawler_instance, scope, stop_event, parallelism)
        self._mitm_port = mitm_port

    async def async_explore(
            self,
            to_explore: deque,
            excluded_urls: list = None
    ) -> AsyncIterator[Tuple[Request, Response]]:
        queue = asyncio.Queue()
        # We don't use to_explore here, clear it.
        to_explore.clear()
        # Launch proxy as asyncio task
        asyncio.create_task(launch_proxy(self._mitm_port, queue, self._crawler.user_agent))
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

        await queue.join()
