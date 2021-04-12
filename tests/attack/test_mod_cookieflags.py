import asyncio
from unittest.mock import Mock

import httpx
import respx
import pytest

from tests.attack.fake_persister import FakePersister
from wapitiCore.net.web import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_cookieflags import mod_cookieflags
from wapitiCore.definitions.secure_cookie import NAME as COOKIE_SECURE_DISABLED
from wapitiCore.definitions.http_only import NAME as COOKIE_HTTPONLY_DISABLED

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

    persister = FakePersister()
    request = Request("https://github.com/")
    request.path_id = 1

    crawler = AsyncCrawler("https://github.com/", timeout=1)
    await crawler.async_send(request)  # Put cookies in our crawler object
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_cookieflags(crawler, persister, logger, options, asyncio.Event())
    await module.attack(request)

    assert persister.module == "cookieflags"
    assert persister.vulnerabilities
    assert persister.vulnerabilities[0]["category"] == COOKIE_HTTPONLY_DISABLED
    assert persister.vulnerabilities[2]["category"] == COOKIE_SECURE_DISABLED
    assert persister.vulnerabilities[0]["info"] == "HttpOnly flag is not set in the cookie : _octo"
    assert persister.vulnerabilities[1]["info"] == "HttpOnly flag is not set in the cookie : foo"
    assert persister.vulnerabilities[2]["info"] == "Secure flag is not set in the cookie : foo"
    await crawler.close()
