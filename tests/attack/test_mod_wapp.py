import json
import lzma
import os
import tempfile
from asyncio import Event
from pathlib import Path
from unittest.mock import AsyncMock, patch, mock_open, ANY

import httpx
from httpx import RequestError
import pytest
import respx

from wapitiCore.attack.mod_wapp import ModuleWapp
from wapitiCore.language.vulnerability import INFO_LEVEL, HIGH_LEVEL, MEDIUM_LEVEL
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net import Request
from wapitiCore.attack.attack import VULN, ADDITION


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

        persister.add_payload.assert_called()

        results = [
            (
                args[1]["payload_type"], args[1]["info"], args[1]["category"]
            ) for args in persister.add_payload.call_args_list
        ]

        expected_results = [
            (
                'additional',
                (
                    '{"name": "Microsoft ASP.NET", "versions": [], "cpe": '
                    '"cpe:2.3:a:microsoft:asp.net:*:*:*:*:*:*:*:*", "categories": ["Web '
                    'frameworks"], "groups": ["Web development"]}'
                ),
                "Fingerprint web technology",
            ),
            (
                'additional',
                (
                    '{"name": "Outlook Web App", "versions": [], "cpe": '
                    '"cpe:2.3:a:microsoft:outlook_web_access:*:*:*:*:*:*:*:*", "categories": '
                    '["Webmail"], "groups": ["Communication"]}'
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
            '{"name": "Atlassian FishEye", "versions": ["2.8.4"], '
            '"cpe": "cpe:2.3:a:atlassian:fisheye:*:*:*:*:*:*:*:*", "categories": '
            '["Development"], "groups": ["Web development"]}'
        )


@pytest.mark.asyncio
@respx.mock
async def test_dom_detection():
    # Test if application is detected using its dom regex
    respx.get("http://perdu.com").mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title> \
            <link href=\"/wp-content/plugins/astra-widgets/test.css?ver=1.5.4\" rel=\"stylesheet\" >\
            </head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong> \
            <input type=\"hidden\" name=\"_glpi_csrf_token\" value=\"b6db36a8c9fd4f3f5d244faa76247688\">\
            <p id=\"mod-sellacious-cart\">test text</p> \
            <p id=\"sm-page-footer-copyright\">SmugMug</p> \
            <img src=\"www.afi-b.com\" /> \
            <a href=\"/cart\">test</a> \
            </body></html>"
        )
    )

    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE") or "/home"
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleWapp(crawler, persister, options, Event(), crawler_configuration)
        await module.attack(request)

        assert persister.add_payload.call_count
        expected_result = [
            '{"name": "Astra Widgets", "versions": ["1.5.4"], "cpe": "", "categories": ["WordPress plugins", "Widgets"], "groups": ["Add-ons", "Other"]}',
            '{"name": "GLPI", "versions": [], "cpe": "cpe:2.3:a:glpi-project:glpi:*:*:*:*:*:*:*:* ", "categories": ["Web frameworks", "CRM"], '
            '"groups": ["Web development", "Marketing", "Business tools"]}',
            '{"name": "Sellacious", "versions": [], "cpe": "", "categories": ["Ecommerce"], "groups": ["Sales"]}',
            '{"name": "SmugMug", "versions": [], "cpe": "", "categories": ["Photo galleries"], "groups": ["Content", "Media"]}',
            '{"name": "Affiliate B", "versions": [], "cpe": "", "categories": ["Affiliate programs", "Advertising"], "groups": ["Marketing"]}',
            '{"name": "Cart Functionality", "versions": [], "cpe": "", "categories": ["Ecommerce"], "groups": ["Sales"]}',
            '{"name": "PHP", "versions": [], "cpe": "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*", "categories": ["Programming languages"], "groups": ["Web development"]}'

        ]
        for arg in persister.add_payload.call_args_list:
            assert arg[1]["info"] in expected_result


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
            '{"name": "Chart.js", "versions": ["1.4.2"], "cpe": "", "categories": ["JavaScript '
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
            '{"name": "CodeIgniter", "versions": ["2+"], "cpe": "cpe:2.3:a:codeigniter:codeigniter:*:*:*:*:*:*:*:*", '
            '"categories": ["Web frameworks"], "groups": ["Web development"]}'
        )


@pytest.mark.asyncio
@respx.mock
async def test_cookies_whatever_value_detection():
    # Test if application is detected using its cookies with empty values
    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong> \
            </body></html>",
            headers={"Set-Cookie": "OJSSID=5646"}
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
            '{"name": "Open Journal Systems", "versions": [], "cpe": "cpe:2.3:a:public_knowledge_project:open_journal_systems:*:*:*:*:*:*:*:*", '
            '"categories": ["DMS"], "groups": ["Content"]}'
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
            '{"name": "Cherokee", "versions": ["1.3.4"], "cpe": "cpe:2.3:a:cherokee-project:cherokee:*:*:*:*:*:*:*:*", '
            '"categories": ["Web servers"], "groups": ["Servers"]}'
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
            '{"name": "Planet", "versions": ["1.6.2"], "cpe": "", "categories": ["Feed readers"], "groups": ["Content"]}'
        )


@pytest.mark.asyncio
@respx.mock
async def test_multi_detection():
    # Directory where GitHub responses are stored
    fixture_folder = Path(__file__).parent.parent / "data" / "wapp"

    # Let's mock wapiti-scanner/nvd-web-cves repository
    wordpress_json_xz_url = (
        "https://github.com/wapiti-scanner/nvd-web-cves/releases/download/"
        "nvd-web-cves-20240808/wordpress.json.xz"
    )

    respx.get("https://api.github.com/repos/wapiti-scanner/nvd-web-cves/releases/latest").mock(
        return_value=httpx.Response(
            status_code=200,
            json={
                "assets": [
                    {
                        "name": "wordpress.json.xz",
                        "browser_download_url": wordpress_json_xz_url,
                    },
                ]
            }
        )
    )

    respx.get(wordpress_json_xz_url).mock(
        return_value=httpx.Response(
            status_code=200,
            content=lzma.compress((fixture_folder / "cve.json").open("rb").read())
        )
    )

    # Now let's mock wapiti-scanner/wappalyzerfork. Wappalyzer files are split over the 1st character of software names.
    for letter, filename in [("m", "mysql.json"), ("p", "php.json"), ("w", "wordpress.json")]:
        respx.get(
            f"https://raw.githubusercontent.com/wapiti-scanner/wappalyzerfork/main/src/technologies/{letter}.json"
        ).mock(
            return_value=httpx.Response(
                status_code=200,
                content=(fixture_folder / filename).open("rb").read(),
                headers={"Content-Type": "application/json"}
            )
        )

    # Give an empty dict for all uninteresting files
    respx.get(url__startswith="https://raw.githubusercontent.com/wapiti-scanner/wappalyzerfork/main/src/techno").mock(
        return_value=httpx.Response(
            status_code=200,
            json={},
        )
    )

    respx.get("https://raw.githubusercontent.com/wapiti-scanner/wappalyzerfork/main/src/categories.json").mock(
        return_value=httpx.Response(
            status_code=200,
            content=(fixture_folder / "categories.json").open("rb").read(),
            headers={"Content-Type": "application/json"}
        )
    )

    respx.get("https://raw.githubusercontent.com/wapiti-scanner/wappalyzerfork/main/src/groups.json").mock(
        return_value=httpx.Response(
            status_code=200,
            content=(fixture_folder / "groups.json").open("rb").read(),
            headers={"Content-Type": "application/json"}
        )
    )

    # Finally we mock the request for Wapiti to scan
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

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        with tempfile.TemporaryDirectory() as temp_dir:
            persister = AsyncMock()
            # To prevent any issue the config directory is a newly created temporary directory
            persister.CONFIG_DIR = temp_dir

            module = ModuleWapp(crawler, persister, options, Event(), crawler_configuration)

            await module.attack(request)

            # Findings:
            # - Fingerprint for Wordpress as a technology
            # - Fingerprint for Wordpress as a framework
            # - Fingerprint for PHP that was deduced from Wordpress
            # - Fingerprint for MySQL that was deduced from Wordpress
            # - Vulnerable software for Wordpress
            assert persister.add_payload.call_count == 5
            assert {parameters[1]["category"] for parameters in persister.add_payload.call_args_list} == {
                "Fingerprint web application framework",
                "Fingerprint web technology",
                "Vulnerable software"
            }

            persister.add_payload.assert_any_call(
                request_id=-1,
                payload_type=VULN,
                module="wapp",
                category="Fingerprint web application framework",
                level=INFO_LEVEL,
                request=request,
                parameter="",
                info='{"name": "WordPress", "versions": ["5.6.1"], "cpe": "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*", "categories": ["CMS", "Blogs"], "groups": ["Content"]}',
                wstg=["WSTG-INFO-08"],
                response=ANY,
            )

            persister.add_payload.assert_any_call(
                request_id=-1,
                payload_type=ADDITION,
                module="wapp",
                category="Fingerprint web technology",
                level=INFO_LEVEL,
                request=request,
                parameter="",
                info='{"name": "PHP", "versions": [], "cpe": "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*", "categories": ["Programming languages"], "groups": ["Web development"]}',
                wstg=['WSTG-INFO-02', 'WSTG-INFO-08'],
                response=ANY,
            )

            persister.add_payload.assert_any_call(
                request_id=-1,
                payload_type=VULN,
                module="wapp",
                category="Vulnerable software",
                # Level is high as we use the most recent CVSS format which is CVSS 3.1 here. Score is 8.8.
                level=HIGH_LEVEL,
                request=request,
                parameter="",
                info=(
                    "wordpress CVE-2022-21664: WordPress is a free and open-source content management system written "
                    "in PHP and paired with a MariaDB database. Due to lack of proper sanitization in one of the "
                    "classes, there's potential for unintended SQL queries to be executed. This has been patched in "
                    "WordPress version 5.8.3. Older affected versions are also fixed via security release, that go "
                    "back till 4.1.34. We strongly recommend that you keep auto-updates enabled. There are no known "
                    "workarounds for this issue."
                ),
                wstg=[],
                response=ANY,
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
            '{"name": "Backdrop", "versions": ["4.5"], "cpe": "cpe:2.3:a:backdropcms:backdrop:*:*:*:*:*:*:*:*", "categories": ["CMS"], "groups": '
            '["Content"]}'
        )
        assert persister.add_payload.call_args_list[-1][1]["info"] == (
            '{"name": "PHP", "versions": [], "cpe": "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*", '
            '"categories": ["Programming languages"], "groups": ["Web development"]}'
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
            '{"name": "Backdrop", "versions": ["4.5"], "cpe": "cpe:2.3:a:backdropcms:backdrop:*:*:*:*:*:*:*:*", "categories": ["CMS"], "groups": ["Content"]}'
        )
        assert persister.add_payload.call_args_list[0][1]["category"] == "Fingerprint web technology"

        assert persister.add_payload.call_args_list[3][1]["info"] == (
            '{"name": "Cherokee", "versions": ["1.3.4"], "cpe": "cpe:2.3:a:cherokee-project:cherokee:*:*:*:*:*:*:*:*", '
            '"categories": ["Web servers"], "groups": ["Servers"]}'
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

        persister.add_payload.assert_called()

        results = [
            (
                args[1]["payload_type"], args[1]["info"], args[1]["category"]
            ) for args in persister.add_payload.call_args_list
        ]

        expected_results = [
            (
                'additional',
                '{"name": "Microsoft ASP.NET", "versions": [], "cpe": "cpe:2.3:a:microsoft:asp.net:*:*:*:*:*:*:*:*", '
                '"categories": ["Web frameworks"], "groups": ["Web development"]}',
                "Fingerprint web technology"
            ),
            (
                'additional',
                '{"name": "Outlook Web App", "versions": ["15.0.1497.26"], "cpe": "cpe:2.3:a:microsoft:outlook_web_access:*:*:*:*:*:*:*:*", '
                '"categories": ["Webmail"], "groups": ["Communication"]}',
                "Fingerprint web technology"
            ),
            (
                'vulnerability',
                '{"name": "Outlook Web App", "versions": ["15.0.1497.26"], "cpe": "cpe:2.3:a:microsoft:outlook_web_access:*:*:*:*:*:*:*:*", '
                '"categories": ["Webmail"], "groups": ["Communication"]}',
                "Fingerprint web application framework"
            ),
        ]

        assert sorted(results) == sorted(expected_results)


@pytest.mark.asyncio
@respx.mock
async def test_raise_on_invalid_json():
    """Tests that a ValueError is raised when calling _dump_url_content_to_file with invalid or empty Json."""

    respx.get("http://perdu.com/src/categories.json").mock(
        return_value=httpx.Response(
            200,
            content="Test"
        )
    )

    persister = AsyncMock()
    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2, "wapp_url": "http://perdu.com"}
        module = ModuleWapp(crawler, persister, options, Event(), crawler_configuration)

        with pytest.raises(ValueError) as exc_info:
            await module._dump_url_content_to_file("http://perdu.com/src/categories.json", "test.json")

        assert exc_info.value.args[0] == "Invalid or empty JSON response for http://perdu.com/src/categories.json"


@pytest.mark.asyncio
@respx.mock
async def test_raise_on_not_valid_db_url():
    """Tests that a ValueError is raised when the URL doesn't contain a Wapp DB."""
    cat_url = "http://perdu.com/src/categories.json"
    group_url = "http://perdu.com/src/groups.json"
    tech_url = "http://perdu.com/src/technologies/"

    respx.get(url__regex=r"http://perdu.com/.*").mock(
        return_value=httpx.Response(
            404,
            content="Not Found"
        )
    )

    persister = AsyncMock()
    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2, "wapp_url": "http://perdu.com/"}

        module = ModuleWapp(crawler, persister, options, Event(), crawler_configuration)

        with pytest.raises(ValueError) as exc_info:
            await module._load_wapp_database(cat_url, tech_url, group_url)

        assert exc_info.value.args[0] == "http://perdu.com/src/technologies/ is not a valid URL for a wapp database"


@pytest.mark.asyncio
@respx.mock
async def test_raise_on_value_error():
    """Tests that a ValueError is raised when calling the _load_wapp_database function when the json is not valid."""

    example_json_content = json.dumps(
        {
            "2B Advice": {
                "cats": [67],
                "description": "2B Advice provides a plug-in to manage GDPR cookie consent.",
                "icon": "2badvice.png",
                "js": {
                    "BBCookieControler": ""
                },
                "saas": True,
                "scriptSrc": "2badvice-cdn\\.azureedge\\.net",
                "website": "https://www.2b-advice.com/en/data-privacy-software/cookie-consent-plugin/"
            },
            "30namaPlayer": {
                "cats": [14],
                "description": "30namaPlayer is a modified version of Video.",
                "dom": "section[class*='player30nama']",
                "icon": "30namaPlayer.png",
                "website": "https://30nama.com/"
            }
        }
    )

    cat_url = "http://perdu.com/src/categories.json"
    group_url = "http://perdu.com/src/groups.json"
    tech_url = "http://perdu.com/src/technologies/"

    respx.get(url__regex=r"http://perdu.com/src/technologies/.*").mock(
        return_value=httpx.Response(
            200,
            content=example_json_content
        )
    )

    respx.get(url__regex=r"http://perdu.com/.*").mock(
        return_value=httpx.Response(
            200,
            content="No Json"
        )
    )

    persister = AsyncMock()
    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2, "wapp_url": "http://perdu.com/"}

        module = ModuleWapp(crawler, persister, options, Event(), crawler_configuration)

        with pytest.raises(ValueError) as exc_info:
            await module._load_wapp_database(cat_url, tech_url, group_url)

        assert exc_info.value.args[0] == "Invalid or empty JSON response for http://perdu.com/src/categories.json"


@pytest.mark.asyncio
@respx.mock
async def test_raise_on_request_error():
    """Tests that a RequestError is raised when calling the _load_wapp_database function with wrong URL."""

    cat_url = "http://perdu.com/src/categories.json"
    group_url = "http://perdu.com/src/groups.json"
    tech_url = "http://perdu.com/src/technologies/"

    respx.get(url__regex=r"http://perdu.com/.*").mock(
        side_effect=RequestError("RequestError occurred: [Errno -2] Name or service not known")
    )

    persister = AsyncMock()
    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2, "wapp_url": "http://perdu.com/"}

        module = ModuleWapp(crawler, persister, options, Event(), crawler_configuration)

        with pytest.raises(RequestError) as exc_info:
            await module._load_wapp_database(cat_url, tech_url, group_url)

        assert exc_info.value.args[0] == "RequestError occurred: [Errno -2] Name or service not known"


@pytest.mark.asyncio
@respx.mock
async def test_raise_on_request_error_for_dump_url():
    """Tests that a RequestError is raised when calling the _dump_url_content_to_file function with wrong URL."""
    url = "http://perdu.com/"

    respx.get(url__regex=r"http://perdu.com/.*").mock(
        side_effect=RequestError("RequestError occurred: [Errno -2] Name or service not known")
    )

    persister = AsyncMock()
    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2, "wapp_url": "http://perdu.com/"}

        module = ModuleWapp(crawler, persister, options, Event(), crawler_configuration)

        with pytest.raises(RequestError) as exc_info:
            await module._dump_url_content_to_file(url, "cat.json")

        assert exc_info.value.args[0] == "RequestError occurred: [Errno -2] Name or service not known"


@pytest.mark.asyncio
@respx.mock
async def test_wappalyzer_raise_on_request_error_for_update():
    """Tests that a RequestError is raised when calling the update function with wrong URL."""
    respx.get(url__regex=r"http://perdu.com/.*").mock(
        side_effect=RequestError("RequestError occurred: [Errno -2] Name or service not known")
    )

    persister = AsyncMock()
    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2, "wapp_url": "http://perdu.com/"}

        module = ModuleWapp(crawler, persister, options, Event(), crawler_configuration)

        with pytest.raises(RequestError) as exc_info:
            await module.update_wappalyzer()

        assert exc_info.value.args[0] == "RequestError occurred: [Errno -2] Name or service not known"


@pytest.mark.asyncio
@respx.mock
async def test_wappalyzer_raise_on_value_error_for_update():
    """Tests that a ValueError is raised when calling the update function with URL doesn't contain a wapp DB."""

    respx.get(url__regex=r"http://perdu.com/src/technologies/.*").mock(
        return_value=httpx.Response(
            200,
            content=str("{}")
        )
    )

    respx.get(url__regex=r"http://perdu.com/.*").mock(
        return_value=httpx.Response(
            200,
            content="No Json"
        )
    )

    persister = AsyncMock()
    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2, "wapp_url": "http://perdu.com/"}

        module = ModuleWapp(crawler, persister, options, Event(), crawler_configuration)

        with pytest.raises(ValueError) as exc_info:
            await module.update_wappalyzer()

        assert exc_info.value.args[0] == "Invalid or empty JSON response for http://perdu.com/src/categories.json"


@pytest.mark.asyncio
@respx.mock
async def test_private_gitlab():
    """Test for private gitlab url and token."""

    techno_json_content = json.dumps(
        {
            "Outlook Web App from test": {
                "cats": [30],
                "cpe": "cpe:2.3:a:microsoft:outlook_web_access:*:*:*:*:*:*:*:*",
                "description": "Outlook on the web is an information manager web app. It includes a web-based email client, a calendar tool, a contact manager, and a task manager.",
                "headers": {"X-OWA-Version": "([\\d\\.]+)?\\;version:\\1"},
                "html": "<link[^>]+/owa/auth/([\\d\\.]+)/themes/resources\\;version:\\1",
                "icon": "Outlook.svg",
                "implies": "Microsoft ASP.NET",
                "js": {"IsOwaPremiumBrowser": ""},
                "url": "/owa/auth/log(?:on|off)\\.aspx",
                "website": "https://help.outlook.com"
            },
            "Microsoft ASP.NET": {
                "cats": [18],
                "cookies": {"ASP.NET_SessionId": "", "ASPSESSION": ""},
                "cpe": "cpe:2.3:a:microsoft:asp.net:*:*:*:*:*:*:*:*",
                "description": "ASP.NET is an open-source, server-side web-application framework designed for web development to produce dynamic web pages.",
                "headers": {
                    "X-AspNet-Version": "(.+)\\;version:\\1",
                    "X-Powered-By": "^ASP\\.NET",
                    "set-cookie": "\\.AspNetCore"
                },
                "html": "<input[^>]+name=\"__VIEWSTATE",
                "icon": "Microsoft ASP.NET.svg",
                "url": "\\.aspx?(?:$|\\?)",
                "website": "https://www.asp.net"
            }
        }
    )

    cat_json_content = json.dumps(
        {
            "30": {
                "groups": [4],
                "name": "Webmail",
                "priority": 2
            },
            "18": {
                "groups": [9],
                "name": "Web frameworks",
                "priority": 7
            }
        }
    )

    group_json_content = json.dumps(
        {
            "4": {
                "name": "Communication"
            },
            "9": {
                "name": "Web development"
            }
        }
    )

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
    respx.get(url__regex=r"http://perdu.com/src%2Ftechnologies%2F.*").mock(
        return_value=httpx.Response(
            200,
            content=techno_json_content
        )
    )
    respx.get("http://perdu.com/src%2Fcategories.json").mock(
        return_value=httpx.Response(
            200,
            content=cat_json_content
        )
    )
    respx.get("http://perdu.com/src%2Fgroups.json").mock(
        return_value=httpx.Response(
            200,
            content=group_json_content
        )
    )

    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE") or "/home"
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config2")

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2, "wapp_url": "http://perdu.com/"}

        with patch.dict(os.environ, {'GITLAB_PRIVATE_TOKEN': 'test_gitlab_private_token'}):
            module = ModuleWapp(crawler, persister, options, Event(), crawler_configuration)
            await module.update_wappalyzer()
            await module.attack(request)

            persister.add_payload.assert_called()

            results = [
                (args[1]["payload_type"], args[1]["info"], args[1]["category"]) for args in
                persister.add_payload.call_args_list
            ]

            expected_results = [
                (
                    'additional',
                    '{"name": "Microsoft ASP.NET", "versions": [], "cpe": "cpe:2.3:a:microsoft:asp.net:*:*:*:*:*:*:*:*", '
                    '"categories": ["Web frameworks"], "groups": ["Web development"]}',
                    "Fingerprint web technology"
                ),
                (
                    'additional',
                    '{"name": "Outlook Web App from test", "versions": ["15.0.1497.26"], "cpe": "cpe:2.3:a:microsoft:outlook_web_access:*:*:*:*:*:*:*:*", '
                    '"categories": ["Webmail"], "groups": ["Communication"]}',
                    "Fingerprint web technology"
                ),
                (
                    'vulnerability',
                    '{"name": "Outlook Web App from test", "versions": ["15.0.1497.26"], "cpe": "cpe:2.3:a:microsoft:outlook_web_access:*:*:*:*:*:*:*:*", '
                    '"categories": ["Webmail"], "groups": ["Communication"]}',
                    "Fingerprint web application framework"
                ),
            ]

            assert sorted(results) == sorted(expected_results)


@pytest.mark.asyncio
@respx.mock
async def test_wappalyzer_raise_on_not_valid_directory_for_update():
    """Tests that a ValueError is raised when calling update() with a directory that does not exist."""
    respx.get(url__regex=r"http://perdu.com/.*").mock(
        return_value=httpx.Response(
            404,
            content="Not Found"
        )
    )
    persister = AsyncMock()
    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2, "wapp_dir": "/"}

        module = ModuleWapp(crawler, persister, options, Event(), crawler_configuration)

        with pytest.raises(ValueError) as exc_info:
            await module.update_wappalyzer()

        assert exc_info.value.args[0] == "Update failed : Something went wrong with files in /"


def read_directory_structure(directory_path):
    file_a_path = os.path.join(directory_path, 'categories.json')
    file_b_path = os.path.join(directory_path, 'groups.json')
    file_c_path = os.path.join(directory_path, 'technologies', 'a.json')

    data_a = read_json_file(file_a_path)
    data_b = read_json_file(file_b_path)
    data_c = read_json_file(file_c_path)

    return {'categories': data_a, 'groups': data_b, 'a': data_c}


def read_json_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        return file.read()


@pytest.mark.asyncio
@respx.mock
async def test_wappalyzer_raise_on_not_valid_json_for_update():
    """Tests that a ValueError is raised when calling update() with an invalid json file."""
    respx.get(url__regex=r"http://perdu.com/.*").mock(
        return_value=httpx.Response(
            404,
            content="Not Found"
        )
    )

    wapp_dir = "wapp/"
    # Mock os.path.isfile to simulate file existence
    with patch('os.path.isfile', side_effect=lambda x: True if x.endswith('.json') else False):
        # Mock os.listdir to simulate the directory structure
        with patch('os.listdir', return_value=['categories.json', 'groups.json', 'technologies']):
            # Mock builtins.open to provide content for the JSON files
            with patch('builtins.open', new_callable=mock_open, read_data='{"key": "value"}'):
                persister = AsyncMock()
                crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
                async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
                    options = {"timeout": 10, "level": 2, "wapp_dir": wapp_dir}

                    module = ModuleWapp(crawler, persister, options, Event(), crawler_configuration)

                    with pytest.raises(ValueError) as exc_info:
                        await module.update_wappalyzer()

            assert exc_info.value.args[0] == "Update failed : Something went wrong with files in wapp/"


@pytest.mark.asyncio
@respx.mock
async def test_wappalyzer_raise_on_not_valid_json_file_for_update():
    """Tests that a ValueError is raised when calling update() with an invalid json file."""
    respx.get(url__regex=r"http://perdu.com/.*").mock(
        return_value=httpx.Response(
            404,
            content="Not Found"
        )
    )

    wapp_dir = "wapp/"
    # Mock os.path.isfile to simulate file existence
    with patch('os.path.isfile', side_effect=lambda x: True if x.endswith('.json') else False):
        # Mock os.listdir to simulate the directory structure
        with patch('os.listdir', return_value=['categories.json', 'groups.json', 'technologies']):
            # Mock builtins.open to provide content for the JSON files
            with patch('builtins.open', new_callable=mock_open, read_data='{"{key "value"}'):
                persister = AsyncMock()
                crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
                async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
                    options = {"timeout": 10, "level": 2, "wapp_dir": wapp_dir}

                    module = ModuleWapp(crawler, persister, options, Event(), crawler_configuration)

                    with pytest.raises(ValueError) as exc_info:
                        await module.update_wappalyzer()

            assert exc_info.value.args[0] == "Update failed : Something went wrong with files in wapp/"


@pytest.mark.asyncio
@respx.mock
async def test_wappalyzer_raise_on_file_does_not_exist_for_update():
    """Tests that a ValueError is raised when calling update() with a missing json file."""
    respx.get(url__regex=r"http://perdu.com/.*").mock(
        return_value=httpx.Response(
            404,
            content="Not Found"
        )
    )

    wapp_dir = "wapp/"
    # Mock os.path.isfile to simulate file existence
    with patch('os.path.isfile', side_effect=lambda x: True if x.endswith('.json') else False):
        # Mock os.listdir to simulate the directory structure
        with patch('os.listdir', return_value=['cat.json', 'gr.json', 'technologie']):
            # Mock builtins.open to provide content for the JSON files
            with patch('builtins.open', new_callable=mock_open, read_data='{"{key "value"}'):
                persister = AsyncMock()
                crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
                async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
                    options = {"timeout": 10, "level": 2, "wapp_dir": wapp_dir}

                    module = ModuleWapp(crawler, persister, options, Event(), crawler_configuration)

                    with pytest.raises(ValueError) as exc_info:
                        await module.update_wappalyzer()

            assert exc_info.value.args[0] == "Update failed : Something went wrong with files in wapp/"


@pytest.mark.asyncio
async def test_get_vulnerabilities():
    cve_data = [
        {
            "id": "CVE-2004-1559",
            "description": "XSS",
            "cvss2": 4.3,
            "versions": [
                "1.2"
            ]
        },
        {
            "id": "CVE-2004-1584",
            "description": "CRLF",
            "cvss2": 5.0,
            "versions": [
                "1.2"
            ]
        },
        {
            "id": "CVE-2005-1102",
            "description": "XSS again",
            "cvss2": 6.8,
            "versions": [
                [
                    None,
                    "<=1.5"
                ]
            ]
        },
    ]
    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        with tempfile.TemporaryDirectory() as temp_dir:
            persister = AsyncMock()
            # To prevent any issue the config directory is a newly created temporary directory
            persister.CONFIG_DIR = temp_dir

            module = ModuleWapp(crawler, persister, options, Event(), crawler_configuration)
            os.mkdir(os.path.join(temp_dir, "cves"))
            with lzma.open(os.path.join(temp_dir, "cves", "wordpress.json.xz"), "wb") as fd:
                fd.write(json.dumps(cve_data).encode())

            results = [
                result async for result in module.get_vulnerabilities(
                    "Wordpress",
                    ["1.2", "1.5"]
                )
            ]
            assert results == [
                (MEDIUM_LEVEL, "Wordpress CVE-2004-1559: XSS"),
                (MEDIUM_LEVEL, "Wordpress CVE-2004-1584: CRLF"),
                (MEDIUM_LEVEL, "Wordpress CVE-2005-1102: XSS again"),
            ]
