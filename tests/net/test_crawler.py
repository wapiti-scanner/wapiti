from itertools import zip_longest

import httpx
import pytest
import respx

from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.net.crawler_configuration import CrawlerConfiguration
from wapitiCore.net.response import Response, Html
from wapitiCore.net.web import Request


@respx.mock
@pytest.mark.asyncio
async def test_extract_disconnect_urls_one_url():
    target_url = "http://perdu.com/"
    respx.get(target_url).mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong><a href='http://perdu.com/foobar/'></a> \
            <a href='http://perdu.com/foobar/signout'></a></body></html>"
        )
    )

    resp = httpx.get(target_url, follow_redirects=False)
    page = Html(Response(resp).content, target_url)

    crawler_configuration = CrawlerConfiguration(Request(target_url), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        disconnect_urls = crawler._extract_disconnect_urls(page)
        assert len(disconnect_urls) == 1


@respx.mock
@pytest.mark.asyncio
async def test_extract_disconnect_urls_no_url():
    target_url = "http://perdu.com/"
    respx.get(target_url).mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong><a href='http://perdu.com/foobar/'></a> \
            <a href='http://perdu.com/foobar/foobar'></a></body></html>"
        )
    )

    resp = httpx.get(target_url, follow_redirects=False)
    page = Html(Response(resp).content, target_url)

    crawler_configuration = CrawlerConfiguration(Request(target_url), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        disconnect_urls = crawler._extract_disconnect_urls(page)
        assert len(disconnect_urls) == 0


@respx.mock
@pytest.mark.asyncio
async def test_extract_disconnect_urls_multiple_urls():
    target_url = "http://perdu.com/"
    respx.get(target_url).mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong><a href='http://perdu.com/foobar/'></a> \
            <a href='http://perdu.com/foobar/signout'></a> \
                <div><a href='http://perdu.com/a/b/signout'></a></div></body></html>"
        )
    )

    resp = httpx.get(target_url, follow_redirects=False)
    page = Html(Response(resp).content, target_url)

    crawler_configuration = CrawlerConfiguration(Request(target_url), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        disconnect_urls = crawler._extract_disconnect_urls(page)
        assert len(disconnect_urls) == 2


@respx.mock
@pytest.mark.asyncio
async def test_async_try_login_post_good_credentials():
    target_url = "http://perdu.com/"
    respx.get(target_url).mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong><a href='http://perdu.com/foobar/'></a> \
            <a href='http://perdu.com/foobar/signout'></a> \
            <form name='loginform' method='post' action='userinfo.php'> \
                <table cellpadding='4' cellspacing='1'> \
                    <tbody><tr><td>Username : </td><td><input name='uname' type='text' size='20'></td></tr> \
                    <tr><td>Password : </td><td><input name='pass' type='password' size='20'></td></tr> \
                    <tr><td colspan='2' align='right'><input type='submit' value='login' style='width:75px;'></td></tr> \
                </tbody></table> \
            </form> \
            <div><a href='http://perdu.com/a/b/signout'></a></div></body></html>"
        )
    )

    respx.post(target_url + 'userinfo.php').mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong><a href='http://perdu.com/foobar/'></a> \
            <a href='http://perdu.com/foobar/signout'>disconnect</a> \
                <div><a href='http://perdu.com/a/b/signout'></a></div></body></html>"
        )
    )

    crawler_configuration = CrawlerConfiguration(Request(target_url), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        crawler._auth_credentials = ["username", "password"]

        is_logged_in, form, disconnect_urls = await crawler._async_try_login_post("username", "password", target_url)

        assert form == {'login_field': 'uname', 'password_field': 'pass'}
        assert len(disconnect_urls) == 2
        assert "http://perdu.com/foobar/signout" in disconnect_urls
        assert "http://perdu.com/a/b/signout" in disconnect_urls
        assert is_logged_in is True


@respx.mock
@pytest.mark.asyncio
async def test_async_try_login_post_wrong_credentials():
    target_url = "http://perdu.com/"
    respx.get(target_url).mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong><a href='http://perdu.com/foobar/'></a> \
            <a href='http://perdu.com/foobar/signout'></a> \
            <form name='loginform' method='post' action='userinfo.php'> \
                <table cellpadding='4' cellspacing='1'> \
                    <tbody><tr><td>Username : </td><td><input name='uname' type='text' size='20'></td></tr> \
                    <tr><td>Password : </td><td><input name='pass' type='password' size='20'></td></tr> \
                    <tr><td colspan='2' align='right'><input type='submit' value='login' style='width:75px;'></td></tr> \
                </tbody></table> \
            </form> \
            <div><a href='http://perdu.com/a/b/signout'></a></div></body></html>"
        )
    )

    respx.post(target_url + 'userinfo.php').mock(
        return_value=httpx.Response(
            401,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong><a href='http://perdu.com/foobar/'></a> \
                <div></div></body></html>"
        )
    )

    crawler_configuration = CrawlerConfiguration(Request(target_url), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        crawler._auth_credentials = ["username", "password"]

        is_logged_in, form, disconnect_urls = await crawler._async_try_login_post("username", "password", target_url)

        assert form == {'login_field': 'uname', 'password_field': 'pass'}
        assert len(disconnect_urls) == 0
        assert is_logged_in is False


@respx.mock
@pytest.mark.asyncio
async def test_async_try_login_post_form_not_detected():
    target_url = "http://perdu.com/"
    respx.get(target_url).mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong><a href='http://perdu.com/foobar/'></a> \
            <a href='http://perdu.com/foobar/signout'></a> \
            <div><a href='http://perdu.com/a/b/signout'></a></div></body></html>"
        )
    )

    crawler_configuration = CrawlerConfiguration(Request(target_url), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        crawler._auth_credentials = ["username", "password"]

        is_logged_in, form, disconnect_urls = await crawler._async_try_login_post("username", "password", target_url)

        assert form == {}
        assert len(disconnect_urls) == 0
        assert is_logged_in is False


@respx.mock
@pytest.mark.asyncio
async def test_async_try_login_basic_digest_ntlm_good_credentials():
    target_url = "http://perdu.com/"
    respx.get(target_url).mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong><a href='http://perdu.com/foobar/'></a> \
            <a href='http://perdu.com/foobar/signout'></a> \
            <div><a href='http://perdu.com/a/b/signout'></a></div></body></html>"
        )
    )

    auth_url = "http://perdu.com/login"
    respx.get(auth_url).mock(
        return_value=httpx.Response(
            200,
            text="OK"
        )
    )

    crawler_configuration = CrawlerConfiguration(Request(target_url), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        crawler._auth_credentials = ["username", "password"]

        is_logged_in, form, disconnect_urls = await crawler._async_try_login_basic_digest_ntlm(auth_url)

        assert is_logged_in is True
        assert len(form) == 0
        assert len(disconnect_urls) == 0


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
async def test_async_try_login_basic_digest_ntlm_wrong_credentials():
    target_url = "http://perdu.com/"
    respx.get(target_url).mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong><a href='http://perdu.com/foobar/'></a> \
            <a href='http://perdu.com/foobar/signout'></a> \
            <div><a href='http://perdu.com/a/b/signout'></a></div></body></html>"
        )
    )

    auth_urls = [
        ["http://perdu.com/login1", 401],
        ["http://perdu.com/login2", 403],
        ["http://perdu.com/login3", 404]
    ]

    crawler_configuration = CrawlerConfiguration(Request(target_url), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        crawler._auth_credentials = ["username", "password"]

        for auth_url, status_code in auth_urls:
            respx.get(auth_url).mock(
                return_value=httpx.Response(
                    status_code,
                    text="KO"
                )
            )

            is_logged_in, form, disconnect_urls = await crawler._async_try_login_basic_digest_ntlm(auth_url)

            assert is_logged_in is False
            assert len(form) == 0
            assert len(disconnect_urls) == 0


@respx.mock
@pytest.mark.asyncio
async def test_extract_disconnect_urls():
    target_url = "http://perdu.com/"
    respx.get(target_url).mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong><a href='http://perdu.com/foobar/'></a> \
            <a href='http://perdu.com/foobar/logout'></a> \
            <a href='http://perdu.com/foobar/logoff'></a> \
            <a href='http://perdu.com/foobar/signout'></a> \
            <a href='http://perdu.com/foobar/signoff'></a> \
            <a href='http://perdu.com/foobar/disconnect'></a> \
            <a href='../../foobar/déconnexion'></a> \
            </div></body></html>"
        )
    )

    crawler_configuration = CrawlerConfiguration(Request(target_url), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        response = await crawler.async_get(Request(target_url))

        page = Html(response.content, target_url)
        disconnect_urls = crawler._extract_disconnect_urls(page)

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

        await crawler.async_send(request, headers)

        assert request.status == 200
        assert request.headers.get("abc") == "123"
        assert "user-agent" in request.sent_headers
        assert request.sent_headers.get("foo") == "bar"
