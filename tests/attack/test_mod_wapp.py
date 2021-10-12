import os
from asyncio import Event

import httpx
import respx
import pytest

from wapitiCore.net.web import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_wapp import mod_wapp
from wapitiCore.language.language import _
from tests import AsyncMock


@pytest.mark.asyncio
@respx.mock
async def test_false_positive():
    # Test for false positive
    respx.route(host="raw.githubusercontent.com").pass_through()

    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong></body></html>"
        )
    )

    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE")
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler = AsyncCrawler("http://perdu.com/")
    options = {"timeout": 10, "level": 2}

    module = mod_wapp(crawler, persister, options, Event())

    await module.attack(request)

    assert not persister.add_payload.call_count
    await crawler.close()


@pytest.mark.asyncio
@respx.mock
async def test_url_detection():
    # Test if application is detected using its url regex
    respx.get("http://perdu.com/owa/auth/logon.aspx").mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong></body></html>"
        )
    )

    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE")
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/owa/auth/logon.aspx")
    request.path_id = 1

    crawler = AsyncCrawler("http://perdu.com/")
    options = {"timeout": 10, "level": 2}

    module = mod_wapp(crawler, persister, options, Event())

    await module.attack(request)

    assert persister.add_payload.call_count
    assert persister.add_payload.call_args_list[0][1]["module"] == "wapp"
    assert persister.add_payload.call_args_list[0][1]["category"] == _("Fingerprint web technology")
    assert persister.add_payload.call_args_list[2][1]["info"] == (
        '{"versions": [], "name": "Outlook Web App", "categories": ["Webmail"], "groups": ["Communication"]}'
    )
    await crawler.close()


@pytest.mark.asyncio
@respx.mock
async def test_html_detection():
    # Test if application is detected using its html regex
    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>FishEye 2.8.4</title> \
            </head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            </body></html>"
        )
    )

    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE")
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler = AsyncCrawler("http://perdu.com/")
    options = {"timeout": 10, "level": 2}

    module = mod_wapp(crawler, persister, options, Event())

    await module.attack(request)

    assert persister.add_payload.call_count
    assert persister.add_payload.call_args_list[0][1]["info"] == (
        '{"versions": ["2.8.4"], "name": "Atlassian FishEye", "categories": ["Development"], "groups": ["Web development"]}'
    )
    await crawler.close()


@pytest.mark.asyncio
@respx.mock
async def test_script_detection():
    # Test if application is detected using its script regex
    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong> \
            <script src=\"http://chartjs.org/dist/1.4.2/Chart.js\"></script>\
            </body></html>"
        )
    )

    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE")
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler = AsyncCrawler("http://perdu.com/")
    options = {"timeout": 10, "level": 2}

    module = mod_wapp(crawler, persister, options, Event())

    await module.attack(request)

    assert persister.add_payload.call_count
    assert persister.add_payload.call_args_list[0][1]["info"] == (
        '{"versions": ["1.4.2"], "name": "Chart.js", "categories": ["JavaScript graphics"], "groups": ["Web development"]}'
    )
    await crawler.close()


@pytest.mark.asyncio
@respx.mock
async def test_cookies_detection():
    # Test if application is detected using its cookies regex
    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong> \
            </body></html>",
            headers={"Set-Cookie": "ci_csrf_token=4.1"}
        )
    )

    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE")
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler = AsyncCrawler("http://perdu.com/")
    options = {"timeout": 10, "level": 2}

    module = mod_wapp(crawler, persister, options, Event())

    await module.attack(request)

    assert persister.add_payload.call_count
    assert persister.add_payload.call_args_list[0][1]["info"] == (
        '{"versions": ["2+"], "name": "CodeIgniter", "categories": ["Web frameworks"], "groups": ["Web development"]}'
    )
    await crawler.close()


@pytest.mark.asyncio
@respx.mock
async def test_headers_detection():
    # Test if application is detected using its headers regex
    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
                    <h2>Pas de panique, on va vous aider</h2> \
                    <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong> \
                    </body></html>",
            headers={"Server": "Cherokee/1.3.4"}
        )
    )

    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE")
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler = AsyncCrawler("http://perdu.com/")
    options = {"timeout": 10, "level": 2}

    module = mod_wapp(crawler, persister, options, Event())

    await module.attack(request)

    assert persister.add_payload.call_count
    assert persister.add_payload.call_args_list[0][1]["info"] == (
        '{"versions": ["1.3.4"], "name": "Cherokee", "categories": ["Web servers"], "groups": ["Servers"]}'
    )
    await crawler.close()


@pytest.mark.asyncio
@respx.mock
async def test_meta_detection():
    # Test if application is detected using its meta regex
    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title> \
            <meta name=\"generator\" content=\"Planet/1.6.2\">    \
            </head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong> \
            </body></html>"
        )
    )

    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE")
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler = AsyncCrawler("http://perdu.com/")
    options = {"timeout": 10, "level": 2}

    module = mod_wapp(crawler, persister, options, Event())

    await module.attack(request)

    assert persister.add_payload.call_count
    assert persister.add_payload.call_args_list[0][1]["info"] == (
        '{"versions": ["1.6.2"], "name": "Planet", "categories": ["Feed readers"], "groups": ["Content"]}'
    )
    await crawler.close()


@pytest.mark.asyncio
@respx.mock
async def test_multi_detection():
    # Test if application is detected using several ways
    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title> \
            <meta name=\"generator\" content=\"WordPress 5.6.1\">    \
            </head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong> \
            <script type=\"text/javascript\" src=\"https://perdu.com/wp-includes/js/wp-embed.min.js\" ></script> \
            </body></html>",
            headers={"link": "<http://perdu.com/wp-json/>; rel=\"https://api.w.org/\""}
        )
    )

    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE")
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler = AsyncCrawler("http://perdu.com/")
    options = {"timeout": 10, "level": 2}

    module = mod_wapp(crawler, persister, options, Event())

    await module.attack(request)

    assert persister.add_payload.call_count
    assert persister.add_payload.call_args_list[-1][1]["info"] == (
        '{"versions": ["5.6.1"], "name": "WordPress", "categories": ["CMS", "Blogs"], "groups": ["Content"]}'
    )
    await crawler.close()


@pytest.mark.asyncio
@respx.mock
async def test_implies_detection():
    # Test for implied applications
    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong> \
            </body></html>",
            headers={"X-Generator": "Backdrop CMS 4.5"}
        )
    )

    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE")
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com")
    request.path_id = 1

    crawler = AsyncCrawler("http://perdu.com")
    options = {"timeout": 10, "level": 2}

    module = mod_wapp(crawler, persister, options, Event())

    await module.attack(request)

    assert persister.add_payload.call_count == 3
    assert persister.add_payload.call_args_list[0][1]["info"] == (
        '{"versions": ["4.5"], "name": "Backdrop", "categories": ["CMS"], "groups": ["Content"]}'
    )
    assert persister.add_payload.call_args_list[-1][1]["info"] == (
        '{"versions": [], "name": "PHP", "categories": ["Programming languages"], "groups": ["Web development"]}'
    )
    await crawler.close()


@pytest.mark.asyncio
@respx.mock
async def test_vulnerabilities():
    # Test for vulnerabilities detected
    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong> \
            </body></html>",
            headers={"X-Generator": "Backdrop CMS 4.5", "Server": "Cherokee/1.3.4"}
        )
    )

    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE")
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com")
    request.path_id = 1

    crawler = AsyncCrawler("http://perdu.com")
    options = {"timeout": 10, "level": 2}

    module = mod_wapp(crawler, persister, options, Event())

    await module.attack(request)

    assert persister.add_payload.call_count == 5
    # FIrst one is an additional
    assert persister.add_payload.call_args_list[0][1]["info"] == (
        '{"versions": ["4.5"], "name": "Backdrop", "categories": ["CMS"], "groups": ["Content"]}'
    )
    assert persister.add_payload.call_args_list[0][1]["category"] == _("Fingerprint web technology")

    assert persister.add_payload.call_args_list[3][1]["info"] == (
        '{"versions": ["1.3.4"], "name": "Cherokee", "categories": ["Web servers"], "groups": ["Servers"]}'
    )
    assert persister.add_payload.call_args_list[3][1]["category"] == _('Fingerprint web server')
    await crawler.close()
