import ssl
from itertools import zip_longest
from unittest.mock import patch

import httpx
import pytest
import respx

from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net.scope import Scope
from wapitiCore.parsers.html_parser import Html
from wapitiCore.net import Request

# pylint: disable=protected-access


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


@pytest.mark.asyncio
async def test_read_timeout_is_not_disabled():
    """Regression for issue #797: a stalled HTTP read must not hang forever.

    The crawler's read timeout used to be None (unbounded), so a server that
    sent its headers then stalled the body blocked ``response.read()``
    indefinitely (the whole scan hung unless --max-scan-time was set). Every
    timeout phase, read included, must honor the configured value.
    """
    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=7)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        assert crawler.timeout.read == 7
        assert crawler.timeout.connect == 7
        assert crawler.timeout.write == 7
        assert crawler.timeout.pool == 7


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


@pytest.mark.asyncio
@respx.mock
async def test_async_get_ssl_error_raises_connect_error():
    target_url = "https://perdu.com/"
    config = CrawlerConfiguration(Request(target_url))
    async with AsyncCrawler.with_configuration(config) as crawler:
        with patch.object(crawler._client, "send", side_effect=ssl.SSLZeroReturnError()):
            with pytest.raises(httpx.ConnectError):
                await crawler.async_get(Request(target_url))


@pytest.mark.asyncio
async def test_async_get_non_ascii_cookie_raises_invalid_url():
    target_url = "https://perdu.com/"
    config = CrawlerConfiguration(Request(target_url))
    async with AsyncCrawler.with_configuration(config) as crawler:
        with patch.object(
            crawler._client,
            "build_request",
            side_effect=UnicodeEncodeError("ascii", "\xbf", 0, 1, "ordinal not in range(128)"),
        ):
            with pytest.raises(httpx.InvalidURL):
                await crawler.async_get(Request(target_url))


@pytest.mark.asyncio
@respx.mock
async def test_async_request_ssl_error_raises_connect_error():
    target_url = "https://perdu.com/"
    config = CrawlerConfiguration(Request(target_url))
    async with AsyncCrawler.with_configuration(config) as crawler:
        with patch.object(crawler._client, "send", side_effect=ssl.SSLZeroReturnError()):
            with pytest.raises(httpx.ConnectError):
                await crawler.async_request("POST", Request(target_url))


@pytest.mark.asyncio
async def test_async_get_unexpected_transport_exception_raises_connect_error():
    # Exceptions not in httpx's hierarchy (e.g. anyio.EndOfStream, trio.ClosedResourceError)
    # that bubble up from the async backend should be wrapped as ConnectError.
    class FakeEndOfStream(Exception):
        pass

    target_url = "https://perdu.com/"
    config = CrawlerConfiguration(Request(target_url))
    async with AsyncCrawler.with_configuration(config) as crawler:
        with patch.object(crawler._client, "send", side_effect=FakeEndOfStream()):
            with pytest.raises(httpx.ConnectError):
                await crawler.async_get(Request(target_url))


@respx.mock
@pytest.mark.asyncio
async def test_too_many_redirections():
    urls = [f"http://perdu.com/{i}" for i in range(8)]
    for current_url, next_url in zip(urls, urls[1:]):
        respx.get(current_url).mock(return_value=httpx.Response(302, headers={"Location": next_url}))
    respx.get(urls[-1]).mock(return_value=httpx.Response(200, text="OK"))

    crawler_configuration = CrawlerConfiguration(Request(urls[0]), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        with pytest.raises(httpx.TooManyRedirects):
            await crawler.async_get(Request(urls[0]), follow_redirects=True)


@respx.mock
@pytest.mark.asyncio
async def test_offsite_redirect_is_not_followed():
    """The target can't drive the scanner to another host through a redirect."""
    respx.get("http://perdu.com/api").mock(
        return_value=httpx.Response(302, headers={"Location": "http://169.254.169.254/latest/meta-data/"})
    )
    metadata_route = respx.get("http://169.254.169.254/latest/meta-data/").mock(
        return_value=httpx.Response(200, text="SECRET")
    )

    crawler_configuration = CrawlerConfiguration(
        Request("http://perdu.com/"), timeout=1, scope=Scope(Request("http://perdu.com/"), "folder")
    )
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        response = await crawler.async_get(Request("http://perdu.com/api"), follow_redirects=True)
        # The caller gets the redirect response itself, as if redirects were not followed
        assert response.status == 302
        assert response.redirection_url == "http://169.254.169.254/latest/meta-data/"
        assert not metadata_route.called

        # Same for a POST, whose body must not be replayed elsewhere either
        respx.post("http://perdu.com/api").mock(
            return_value=httpx.Response(307, headers={"Location": "http://169.254.169.254/latest/meta-data/"})
        )
        response = await crawler.async_send(
            Request("http://perdu.com/api", post_params=[["a", "b"]]), follow_redirects=True
        )
        assert response.status == 307
        assert not metadata_route.called

        # Another port of the same host over plain HTTP is another service: not followed either
        respx.get("http://perdu.com/other").mock(
            return_value=httpx.Response(302, headers={"Location": "http://perdu.com:6379/"})
        )
        other_port_route = respx.get("http://perdu.com:6379/").mock(return_value=httpx.Response(200, text="PONG"))
        response = await crawler.async_get(Request("http://perdu.com/other"), follow_redirects=True)
        assert response.status == 302
        assert not other_port_route.called


@respx.mock
@pytest.mark.asyncio
async def test_same_host_and_in_scope_redirects_are_followed():
    respx.get("http://perdu.com/").mock(return_value=httpx.Response(302, headers={"Location": "https://perdu.com:8443/"}))
    respx.get("https://perdu.com:8443/").mock(
        return_value=httpx.Response(302, headers={"Location": "https://www.perdu.com/home"})
    )
    respx.get("https://www.perdu.com/home").mock(return_value=httpx.Response(200, text="OK"))

    # Scheme and port changes on the same host are always fine, another host of the domain needs the scope
    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        response = await crawler.async_get(Request("http://perdu.com/"), follow_redirects=True)
        assert response.status == 302
        assert response.url == "https://perdu.com:8443/"
        assert len(response.history) == 1

    crawler_configuration.scope = Scope(Request("http://perdu.com/"), "domain")
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        response = await crawler.async_get(Request("http://perdu.com/"), follow_redirects=True)
        assert response.status == 200
        assert response.url == "https://www.perdu.com/home"
        assert [page.status for page in response.history] == [302, 302]


@respx.mock
@pytest.mark.asyncio
async def test_offsite_redirect_allowed_on_demand():
    respx.get("http://perdu.com/download").mock(
        return_value=httpx.Response(302, headers={"Location": "http://cdn.example.com/file"})
    )
    cdn_route = respx.get("http://cdn.example.com/file").mock(return_value=httpx.Response(200, text="DATA"))

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        response = await crawler.async_get(
            Request("http://perdu.com/download"), follow_redirects=True, allow_offsite_redirects=True
        )
        assert response.status == 200
        assert response.content == "DATA"
        assert cdn_route.called
