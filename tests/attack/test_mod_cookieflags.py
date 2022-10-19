import asyncio
import re
from unittest.mock import AsyncMock

import httpx
import respx
import pytest

from wapitiCore.net import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.attack.mod_cookieflags import ModuleCookieflags


@pytest.mark.asyncio
@respx.mock
async def test_cookieflags():
    respx.get("https://github.com/").mock(
        return_value=httpx.Response(
            200,
            headers=[
                ("set-cookie", "_octo=31337; Path=/; Domain=github.com; Secure; SameSite=Lax"),
                ("set-cookie", "logged_in=no; Path=/; Domain=github.com; HttpOnly; Secure; SameSite=Lax"),
                ("set-cookie", "foo=bar; Path=/; Domain=github.com;")
            ]
        )
    )

    persister = AsyncMock()
    request = Request("https://github.com/")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("https://github.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        await crawler.async_send(request)  # Put cookies in our crawler object
        options = {"timeout": 10, "level": 2}

        module = ModuleCookieflags(crawler, persister, options, asyncio.Event(), crawler_configuration)
        await module.attack(request)

        cookie_flags = []
        assert persister.add_payload.call_count == 3
        assert persister.add_payload.call_args_list[0][1]["module"] == "cookieflags"
        for call in persister.add_payload.call_args_list:
            description, cookie_name = call[1]["info"].split(":")
            cookie_flags.append((cookie_name.strip(), re.search(r"(HttpOnly|Secure)", description).group()))

        assert cookie_flags == [
            ('_octo', 'HttpOnly'),
            ('foo', 'HttpOnly'),
            ('foo', 'Secure')
        ]
