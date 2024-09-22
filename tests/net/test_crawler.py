from itertools import zip_longest

import httpx
import pytest
import respx

from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.net.classes import CrawlerConfiguration, HttpCredential, FormCredential, RawCredential
from wapitiCore.parsers.html_parser import Html
from wapitiCore.net import Request
from wapitiCore.net.auth import async_try_form_login, check_http_auth, login_with_raw_data


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
                    <tr><td colspan='2' align='right'><input type='submit' value='login'></td></tr> \
                </tbody></table> \
            </form> \
            <div><a href='http://perdu.com/a/b/signout'></a></div></body></html>",
            headers={"Set-Cookie": "1st_stage=success;"}
        )
    )

    respx.post(target_url + 'userinfo.php', data={"uname": "username", "pass": "password"}).mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong><a href='http://perdu.com/foobar/'></a> \
            <a href='http://perdu.com/foobar/signout'>disconnect</a> \
                <div><a href='http://perdu.com/a/b/signout'></a></div></body></html>",
            headers={"Set-Cookie": "2nd_stage=success;"}
        )
    )

    crawler_configuration = CrawlerConfiguration(Request(target_url), timeout=1)
    form_credential = FormCredential("username", "password", target_url)
    is_logged_in, form, disconnect_urls = await async_try_form_login(crawler_configuration, form_credential)

    assert form == {'login_field': 'uname', 'password_field': 'pass'}
    assert len(disconnect_urls) == 2
    assert "http://perdu.com/foobar/signout" in disconnect_urls
    assert "http://perdu.com/a/b/signout" in disconnect_urls
    assert is_logged_in is True
    assert [
               ("1st_stage", "success"), ("2nd_stage", "success")
           ] == [(cookie.name, cookie.value) for cookie in crawler_configuration.cookies]


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
                    <tr><td colspan='2' align='right'><input type='submit' value='login'></td></tr> \
                </tbody></table> \
            </form> \
            <div><a href='http://perdu.com/a/b/signout'></a></div></body></html>"
        )
    )

    respx.post(target_url + 'userinfo.php', data={"uname": "username", "pass": "password"}).mock(
        return_value=httpx.Response(
            401,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong><a href='http://perdu.com/foobar/'></a> \
                <div></div></body></html>",
            headers={"Set-Cookie": "at_least=you_tried;"}
        )
    )

    crawler_configuration = CrawlerConfiguration(Request(target_url), timeout=1)

    form_credential = FormCredential("username", "password", target_url)

    is_logged_in, form, disconnect_urls = await async_try_form_login(crawler_configuration, form_credential)

    assert form == {'login_field': 'uname', 'password_field': 'pass'}
    assert len(disconnect_urls) == 0
    assert is_logged_in is False
    assert [("at_least", "you_tried")] == [(cookie.name, cookie.value) for cookie in crawler_configuration.cookies]


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
            <div><a href='http://perdu.com/a/b/signout'></a></div></body></html>",
            headers={"Set-Cookie": "success=false;"}
        )
    )

    crawler_configuration = CrawlerConfiguration(Request(target_url), timeout=1)
    form_credential = FormCredential("username", "password", target_url)

    is_logged_in, form, disconnect_urls = await async_try_form_login(crawler_configuration, form_credential)

    assert form == {}
    assert len(disconnect_urls) == 0
    assert is_logged_in is False
    assert [("success", "false")] == [(cookie.name, cookie.value) for cookie in crawler_configuration.cookies]


@respx.mock
@pytest.mark.asyncio
async def test_async_login_raw_credentials():
    target_url = "http://perdu.com/userinfo.php"
    crawler_configuration = CrawlerConfiguration(Request(target_url), timeout=1)
    raw_credential = RawCredential(
        "uname=besthacker&pass=letmein",
        target_url
    )
    respx.post(target_url, data={"uname": "besthacker", "pass": "letmein"}).mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong><a href='http://perdu.com/foobar/'></a> \
            <a href='http://perdu.com/foobar/signout'>disconnect</a> \
                <div><a href='http://perdu.com/a/b/signout'></a></div></body></html>",
            headers={"Set-Cookie": "login=besthacker;"}
        )
    )

    await login_with_raw_data(crawler_configuration, raw_credential)
    assert [("login", "besthacker")] == [(cookie.name, cookie.value) for cookie in crawler_configuration.cookies]


@respx.mock
@pytest.mark.asyncio
async def test_async_login_json_credentials():
    target_url = "http://perdu.com/userinfo.php"
    crawler_configuration = CrawlerConfiguration(Request(target_url), timeout=1)
    raw_credential = RawCredential(
        """{"uname": "besthacker", "pass": "letmein"}""",
        target_url,
        enctype="application/json"
    )
    respx.post(
        target_url,
        json={"uname": "besthacker", "pass": "letmein"},
        headers={"Content-Type": "application/json"},
    ).mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong><a href='http://perdu.com/foobar/'></a> \
            <a href='http://perdu.com/foobar/signout'>disconnect</a> \
                <div><a href='http://perdu.com/a/b/signout'></a></div></body></html>",
            headers={"Set-Cookie": "login=besthacker;"}
        )
    )

    await login_with_raw_data(crawler_configuration, raw_credential)
    assert [("login", "besthacker")] == [(cookie.name, cookie.value) for cookie in crawler_configuration.cookies]


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
    crawler_configuration.http_credential = HttpCredential("username", "password")
    auth_success = await check_http_auth(crawler_configuration)

    assert auth_success is True


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
            401,
            text="<html><head><title>Forbidden</title></head><body></body></html>"
        )
    )

    crawler_configuration = CrawlerConfiguration(Request(target_url), timeout=1)
    crawler_configuration.http_credential = HttpCredential("username", "password")

    auth_success = await check_http_auth(crawler_configuration)

    assert auth_success is False


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
        assert "user-agent" in request.headers
        assert request.headers.get("foo") == "bar"


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
