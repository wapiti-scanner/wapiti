"""Tests of click_in_webpage with a real browser: a mocked page accepts any selector, Playwright doesn't."""
import asyncio
import time

import pytest
from playwright.async_api import async_playwright

from wapitiCore.net import Request
from wapitiCore.net.intercepting_explorer import click_in_webpage

PAGE_URL = "http://wapiti.test/"

PAGE_BODY = """<html>
<body>
<div style="display: none">
  <button onclick="fetch('/hidden-button')">Hidden</button>
  <span role="button" onclick="fetch('/hidden-role')">Hidden too</span>
</div>
<button type="button" onclick="fetch('/button')">Visible</button>
<span role="button" onclick="fetch('/role')">Visible too</span>
<a role="button" href="/link">Link with a button role</a>
</body>
</html>"""


async def click_and_collect_paths(timeout: float) -> list:
    seen_paths = []

    async def handle_route(route):
        path = route.request.url.removeprefix(PAGE_URL)
        if path:
            # The answer takes some time: the crawler must wait for it before leaving the page
            await asyncio.sleep(0.5)
            await route.fulfill(status=200, content_type="text/plain", body="ok")
            seen_paths.append(path)
        else:
            await route.fulfill(status=200, content_type="text/html", body=PAGE_BODY)

    async with async_playwright() as playwright:
        browser = await playwright.firefox.launch(headless=True)
        try:
            page = await browser.new_page()
            await page.route("**/*", handle_route)
            await page.goto(PAGE_URL)
            await click_in_webpage(page, Request(PAGE_URL), wait_time=1., timeout=timeout)
        finally:
            await browser.close()

    return seen_paths


@pytest.mark.asyncio
async def test_click_in_webpage_clicks_visible_buttons():
    seen_paths = await click_and_collect_paths(timeout=5.)

    # Links are followed by the crawler itself, they must not be clicked
    assert sorted(seen_paths) == ["button", "role"]


@pytest.mark.asyncio
async def test_click_in_webpage_does_not_wait_for_hidden_buttons():
    timeout = 20.
    start = time.monotonic()
    await click_and_collect_paths(timeout=timeout)

    # Each hidden button used to cost the whole click timeout
    assert time.monotonic() - start < timeout
