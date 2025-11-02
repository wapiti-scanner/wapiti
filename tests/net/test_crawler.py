from itertools import zip_longest

import httpx
import pytest
import respx

from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.parsers.html_parser import Html
from wapitiCore.net import Request


def test_extract_disconnect_urls_one_url():
    target_url = "http://perdu.com/"
    text = (
        "<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1>"
        "<h2>Pas de panique, on va vous aider</h2>"
        "<strong><pre>    * <----- vous &ecirc;tes ici</pre></strong><a href='http://perdu.com/foobar/'></a>"
        "<a href='http://perdu.com/foobar/signout'></a></body></html>"
    )

    page = Html(text, target_url)
    assert len(page.extract_disconnect_urls()) == 1


def test_extract_disconnect_urls_no_url():
    target_url = "http://perdu.com/"
    text = (
        "<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1>"
        "<h2>Pas de panique, on va vous aider</h2>"
        "<strong><pre>    * <----- vous &ecirc;tes ici</pre></strong><a href='http://perdu.com/foobar/'></a>"
        "<a href='http://perdu.com/foobar/foobar'></a></body></html>"
    )

    page = Html(text, target_url)
    assert len(page.extract_disconnect_urls()) == 0


def test_extract_disconnect_urls_multiple_urls():
    target_url = "http://perdu.com/"
    text = (
        "<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1>"
        "<h2>Pas de panique, on va vous aider</h2>"
        "<strong><pre>    * <----- vous &ecirc;tes ici</pre></strong><a href='http://perdu.com/foobar/'></a>"
        "<a href='http://perdu.com/foobar/signout'></a>"
        "<div><a href='http://perdu.com/a/b/signout'></a></div></body></html>"
    )

    page = Html(text, target_url)
    assert len(page.extract_disconnect_urls()) == 2


@respx.mock
@pytest.mark.asyncio
async def test_multiple_redirecton():
    target_url = "http://perdu.com/"
    redirected_urls = [
        target_url,
        "http://perdu.com/2",
        "http://perdu.com/3",
        "http://perdu.com/4",
        "http://perdu.com/5",
    ]

    for current_url, next_url in zip_longest(redirected_urls, redirected_urls[1:], fillvalue=None):
        respx.get(current_url).mock(
            return_value=httpx.Response(
                302 if next_url else 200,
                headers={"Location": next_url} if next_url else None,
                text="redirect" if next_url else "OK"
            )
        )

    crawler_configuration = CrawlerConfiguration(Request(target_url), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        response = await crawler.async_get(Request(target_url), follow_redirects=True)
        assert response.status == 200
        assert response.content == "OK"


def test_extract_disconnect_urls():
    target_url = "http://perdu.com/"
    text = (
        "<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1>"
        "<h2>Pas de panique, on va vous aider</h2>"
        "<strong><pre>    * <----- vous &ecirc;tes ici</pre></strong><a href='http://perdu.com/foobar/'></a>"
        "<a href='http://perdu.com/foobar/logout'></a>"
        "<a href='http://perdu.com/foobar/logoff'></a>"
        "<a href='http://perdu.com/foobar/signout'></a>"
        "<a href='http://perdu.com/foobar/signoff'></a>"
        "<a href='http://perdu.com/foobar/disconnect'></a>"
        "<a href='../../foobar/déconnexion'></a>"
        "</div></body></html>"
    )

    page = Html(text, target_url)
    disconnect_urls = page.extract_disconnect_urls()

    test_disconnect_urls = [
        "http://perdu.com/foobar/logout",
        "http://perdu.com/foobar/logoff",
        "http://perdu.com/foobar/signout",
        "http://perdu.com/foobar/signoff",
        "http://perdu.com/foobar/disconnect",
        "http://perdu.com/foobar/déconnexion"
    ]

    assert len(disconnect_urls) == len(test_disconnect_urls)
    assert all(url in disconnect_urls for url in test_disconnect_urls) is True


@respx.mock
@pytest.mark.asyncio
async def test_async_send():
    request = Request("http://perdu.com/", "GET")

    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            status_code=200,
            text="<div><a href='http://perdu.com/a/b/signout'></a></div></body></html>",
            headers={"abc": "123"}
        )
    )

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        headers = {
            "foo": "bar"
        }

        response = await crawler.async_send(request, headers)

        assert response.status == 200
        assert response.headers.get("abc") == "123"
        assert "user-agent" in request.sent_headers
        assert request.sent_headers.get("foo") == "bar"


@respx.mock
@pytest.mark.asyncio
async def test_async_put_enctype():
    request = Request("http://perdu.com/", "PUT", post_params='{"id": 31337}', enctype="application/json")

    route = respx.put("http://perdu.com/").mock(
        return_value=httpx.Response(
            status_code=200,
            text="Whatever",
        )
    )

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        await crawler.async_send(request)

        assert route.called
        # Check if the request headers contain the expected headers
        caught_request = route.calls[0].request
        assert caught_request.headers["Content-Type"] == "application/json"


@respx.mock
@pytest.mark.asyncio
async def test_async_put_missing_enctype():
    request = Request("http://perdu.com/", "PUT", post_params='a=b')

    route = respx.put("http://perdu.com/").mock(
        return_value=httpx.Response(
            status_code=200,
            text="Whatever",
        )
    )

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        await crawler.async_send(request)

        # Check if the request was made
        assert route.called
        # Check if the request headers contain the expected headers
        caught_request = route.calls[0].request
        assert caught_request.headers["Content-Type"] == "application/x-www-form-urlencoded"
        assert caught_request.content == b"a=b"


@pytest.mark.asyncio
@respx.mock
async def test_cookie_priority():
    set_cookie_url = "http://httpbin.org/set-cookie"
    read_cookie_url = "http://httpbin.org/cookies"

    # This route will set the "fresh" cookie
    respx.get(set_cookie_url).mock(
        return_value=httpx.Response(200, headers={"Set-Cookie": "session=fresh"})
    )
    # This is the route we will check for the sent cookie
    read_cookie_route = respx.get(read_cookie_url).mock(return_value=httpx.Response(200))

    config = CrawlerConfiguration(Request(read_cookie_url))
    # Crawler starts with an empty cookie jar

    async with AsyncCrawler.with_configuration(config) as crawler:
        # 1. First, visit the page that sets the fresh cookie
        await crawler.async_send(Request(set_cookie_url))

        # 2. Then, try to send a request with a stale cookie in its headers
        stale_req = Request(read_cookie_url, headers={"Cookie": "session=stale"})
        await crawler.async_send(stale_req)

    assert read_cookie_route.called
    sent_headers = read_cookie_route.calls[0].request.headers
    assert sent_headers["cookie"] == "session=fresh"
