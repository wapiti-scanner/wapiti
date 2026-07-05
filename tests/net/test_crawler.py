import base64
import ssl
from itertools import zip_longest
from unittest.mock import patch

import httpx
import pytest
import respx
import spnego

from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.net.classes import CrawlerConfiguration, HttpCredential
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


@respx.mock
@pytest.mark.asyncio
async def test_redirect_with_invalid_location_is_returned():
    # A redirect response whose Location is not a valid URL (here a data: URI) used to make httpx
    # raise InvalidURL while building the redirect request, even with follow_redirects=False, so the
    # response never reached the caller and its headers were lost. httpxyz returns the response as-is.
    # Regression test for https://github.com/wapiti-scanner/wapiti/issues/690
    target_url = "http://perdu.com/redirect"
    location = "data:;base64,PD9waHAgZWNobyAndzRwMXQxJywnX2V2YWwnOyA/Pg=="
    respx.get(target_url).mock(return_value=httpx.Response(302, headers={"Location": location}))

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        response = await crawler.async_send(Request(target_url), follow_redirects=False)

    assert response.status == 302
    assert response.headers["location"] == location


@respx.mock
@pytest.mark.asyncio
async def test_ntlm_authentication(tmp_path, monkeypatch):
    # NTLM auth relies on the third-party httpx-ntlm, which only works with httpxyz through the
    # sys.modules alias (it does "from httpx import Auth"). Drive a full NTLM handshake against a
    # pyspnego acceptor to make sure HttpNtlmAuth still authenticates on the (aliased) client.
    domain, user, password = "DOMAIN", "user", "Password123!"
    cred_file = tmp_path / "ntlm_creds"
    cred_file.write_text(f"{domain}:{user}:{password}\n")
    monkeypatch.setenv("NTLM_USER_FILE", str(cred_file))  # pyspnego acceptor credential store

    server_ctx = spnego.server(protocol="ntlm")

    def responder(request):
        authorization = request.headers.get("authorization")
        if not authorization:
            return httpx.Response(401, headers={"WWW-Authenticate": "NTLM"})
        token = base64.b64decode(authorization.split(" ", 1)[1])
        out = server_ctx.step(token)
        if not server_ctx.complete:
            return httpx.Response(401, headers={"WWW-Authenticate": f"NTLM {base64.b64encode(out).decode()}"})
        return httpx.Response(200, text="authenticated")

    respx.get("http://ntlm.test/").mock(side_effect=responder)

    crawler_configuration = CrawlerConfiguration(
        Request("http://ntlm.test/"),
        http_credential=HttpCredential(username=f"{domain}\\{user}", password=password, method="ntlm"),
        timeout=5,
    )
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        response = await crawler.async_send(Request("http://ntlm.test/"))

    assert response.status == 200
    assert response.content == "authenticated"
    assert server_ctx.complete


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
