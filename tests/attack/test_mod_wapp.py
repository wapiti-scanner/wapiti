import os
from asyncio import Event
from unittest.mock import AsyncMock

import httpx
import pytest
import respx

from wapitiCore.attack.mod_wapp import ModuleWapp
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net import Request


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
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE") or "/home"
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleWapp(crawler, persister, options, Event(), crawler_configuration)

        await module.attack(request)

        assert not persister.add_payload.call_count


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
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE") or "/home"
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/owa/auth/logon.aspx")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleWapp(crawler, persister, options, Event(), crawler_configuration)

        await module.attack(request)

        persister.add_payload.assert_called

        results = [
            (
                args[1]["payload_type"], args[1]["info"], args[1]["category"]
            ) for args in persister.add_payload.call_args_list
        ]

        expected_results = [
            (
                'additional',
                (
                    '{"name": "Microsoft ASP.NET", "versions": [], "categories": ["Web '
                    'frameworks"], "groups": ["Web development"]}'
                ),
                "Fingerprint web technology",
            ),
            (
                'additional',
                (
                    '{"name": "Outlook Web App", "versions": [], "categories": ["Webmail"], '
                    '"groups": ["Communication"]}'
                ),
                "Fingerprint web technology",
            )
        ]

        assert sorted(results) == sorted(expected_results)


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
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE") or "/home"
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleWapp(crawler, persister, options, Event(), crawler_configuration)

        await module.attack(request)

        assert persister.add_payload.call_count
        assert persister.add_payload.call_args_list[0][1]["info"] == (
            '{"name": "Atlassian FishEye", "versions": ["2.8.4"], "categories": '
            '["Development"], "groups": ["Web development"]}'
        )


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
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE") or "/home"
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleWapp(crawler, persister, options, Event(), crawler_configuration)

        await module.attack(request)

        assert persister.add_payload.call_count
        assert persister.add_payload.call_args_list[0][1]["info"] == (
            '{"name": "Chart.js", "versions": ["1.4.2"], "categories": ["JavaScript '
            'graphics"], "groups": ["Web development"]}'
        )


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
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE") or "/home"
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleWapp(crawler, persister, options, Event(), crawler_configuration)

        await module.attack(request)

        assert persister.add_payload.call_count
        assert persister.add_payload.call_args_list[0][1]["info"] == (
            '{"name": "CodeIgniter", "versions": ["2+"], "categories": ["Web '
            'frameworks"], "groups": ["Web development"]}'
        )


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
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE") or "/home"
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleWapp(crawler, persister, options, Event(), crawler_configuration)

        await module.attack(request)

        assert persister.add_payload.call_count
        assert persister.add_payload.call_args_list[0][1]["info"] == (
            '{"name": "Cherokee", "versions": ["1.3.4"], "categories": ["Web servers"], "groups": ["Servers"]}'
        )


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
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE") or "/home"
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleWapp(crawler, persister, options, Event(), crawler_configuration)

        await module.attack(request)

        assert persister.add_payload.call_count
        assert persister.add_payload.call_args_list[0][1]["info"] == (
            '{"name": "Planet", "versions": ["1.6.2"], "categories": ["Feed readers"], "groups": ["Content"]}'
        )


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
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE") or "/home"
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleWapp(crawler, persister, options, Event(), crawler_configuration)

        await module.attack(request)

        assert persister.add_payload.call_count
        assert persister.add_payload.call_args_list[-1][1]["info"] == (
            '{"name": "WordPress", "versions": ["5.6.1"], "categories": ["CMS", "Blogs"], '
            '"groups": ["Content"]}'
        )


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
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE") or "/home"
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleWapp(crawler, persister, options, Event(), crawler_configuration)

        await module.attack(request)

        assert persister.add_payload.call_count == 3
        assert persister.add_payload.call_args_list[0][1]["info"] == (
            '{"name": "Backdrop", "versions": ["4.5"], "categories": ["CMS"], "groups": '
            '["Content"]}'
        )
        assert persister.add_payload.call_args_list[-1][1]["info"] == (
            '{"name": "PHP", "versions": [], "categories": ["Programming languages"], '
            '"groups": ["Web development"]}'
        )


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
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE") or "/home"
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleWapp(crawler, persister, options, Event(), crawler_configuration)

        await module.attack(request)

        assert persister.add_payload.call_count == 5
        # FIrst one is an additional
        assert persister.add_payload.call_args_list[0][1]["info"] == (
            '{"name": "Backdrop", "versions": ["4.5"], "categories": ["CMS"], "groups": ["Content"]}'
        )
        assert persister.add_payload.call_args_list[0][1]["category"] == "Fingerprint web technology"

        assert persister.add_payload.call_args_list[3][1]["info"] == (
            '{"name": "Cherokee", "versions": ["1.3.4"], "categories": ["Web servers"], "groups": ["Servers"]}'
        )
        assert persister.add_payload.call_args_list[3][1]["category"] == "Fingerprint web server"


@pytest.mark.asyncio
@respx.mock
async def test_merge_with_and_without_redirection():
    # Test for vulnerabilities detected
    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            301,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong> \
            </body></html>",
            headers={"X-OWA-Version": "15.0.1497.26", "Location": "http://perdu.com/auth/login"}
        )
    )
    respx.get("http://perdu.com/auth/login").mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <link rel='shortcut icon' href='/owa/auth/15.0.1497/themes/resources/favicon.ico' type='image/x-icon'> \
            <h2>Pas de panique, on va vous aider</h2> \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong> \
            </body></html>",
            headers={}
        )
    )

    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE") or "/home"
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleWapp(crawler, persister, options, Event(), crawler_configuration)

        await module.attack(request)

        persister.add_payload.assert_called

        results = [
            (
                args[1]["payload_type"], args[1]["info"], args[1]["category"]
            ) for args in persister.add_payload.call_args_list
        ]

        expected_results = [
            (
                'additional',
                '{"name": "Microsoft ASP.NET", "versions": [], "categories": ["Web frameworks"], "groups": ["Web development"]}',
                "Fingerprint web technology"
            ),
            (
                'additional',
                '{"name": "Outlook Web App", "versions": ["15.0.1497.26"], "categories": ["Webmail"], "groups": ["Communication"]}',
                "Fingerprint web technology"
            ),
            (
                'vulnerability',
                '{"name": "Outlook Web App", "versions": ["15.0.1497.26"], "categories": ["Webmail"], "groups": ["Communication"]}',
                "Fingerprint web application framework"
            ),
        ]

        assert sorted(results) == sorted(expected_results)
