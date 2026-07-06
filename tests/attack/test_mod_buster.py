import logging
from unittest import mock
from unittest.mock import AsyncMock
from asyncio import sleep

import httpx
import respx
import pytest

from wapitiCore.net import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.attack.mod_buster import ModuleBuster
from tests import AsyncIterator, get_mock_open


@pytest.mark.asyncio
@respx.mock
async def test_whole_stuff():
    # Test attacking all kind of parameter without crashing
    respx.get("http://perdu.com/").mock(return_value=httpx.Response(200, text="Default page"))
    respx.get("http://perdu.com/admin").mock(
        return_value=httpx.Response(301, text="Hello there", headers={"Location": "/admin/"})
    )
    respx.get("http://perdu.com/admin/").mock(return_value=httpx.Response(200, text="Hello there"))
    respx.get("http://perdu.com/config.inc").mock(return_value=httpx.Response(200, text="pass = 123456"))
    respx.get("http://perdu.com/admin/authconfig.php").mock(return_value=httpx.Response(200, text="Hello there"))
    respx.get(url__regex=r"http://perdu\.com/.*").mock(return_value=httpx.Response(404))

    persister = AsyncMock()

    request = Request("http://perdu.com/")
    request.path_id = 1
    # Buster module will get requests from the persister
    persister.get_links = AsyncIterator([(request, None)])

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2, "tasks": 20}

        files = {
            "wordlist.txt": "nawak\nadmin\nconfig.inc\nauthconfig.php",
        }
        with mock.patch("builtins.open", get_mock_open(files)):
            module = ModuleBuster(crawler, persister, options, crawler_configuration)
            module.DATA_DIR = ""
            module.PATHS_FILE = "wordlist.txt"
            module.do_get = True
            await module.attack(request)

            assert module.known_dirs == ["http://perdu.com/", "http://perdu.com/admin/"]
            assert module.known_pages == ["http://perdu.com/config.inc", "http://perdu.com/admin/authconfig.php"]
        assert persister.add_payload.call_count == 3
        assert "http://perdu.com/admin" in persister.add_payload.call_args_list[0][1]["info"]
        assert "http://perdu.com/config.inc" in persister.add_payload.call_args_list[1][1]["info"]
        assert "http://perdu.com/admin/authconfig.php" in persister.add_payload.call_args_list[2][1]["info"]


@pytest.mark.asyncio
@respx.mock
async def test_soft_404():
    # The server returns a 200 "not found" page for every unknown path (soft 404).
    # Only paths whose body clearly differs from that generic page must be reported.
    soft_404_body = "<html><body><h1>Sorry, this page does not exist</h1></body></html>"

    respx.get("http://perdu.com/").mock(return_value=httpx.Response(200, text="Default page"))
    # A real, discoverable page with a distinctive body
    respx.get("http://perdu.com/secret").mock(
        return_value=httpx.Response(200, text="Top secret administration console")
    )
    # Everything else (the improbable probe and the other candidates) is a soft 404
    respx.get(url__regex=r"http://perdu\.com/.*").mock(return_value=httpx.Response(200, text=soft_404_body))

    persister = AsyncMock()
    request = Request("http://perdu.com/")
    request.path_id = 1
    persister.get_links = AsyncIterator([(request, None)])

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2, "tasks": 20}

        files = {"wordlist.txt": "nawak\nsecret\nanother"}
        with mock.patch("builtins.open", get_mock_open(files)):
            module = ModuleBuster(crawler, persister, options, crawler_configuration)
            module.DATA_DIR = ""
            module.PATHS_FILE = "wordlist.txt"
            module.do_get = True
            await module.attack(request)

        # Only /secret should be reported, the soft-404 candidates must be discarded
        assert persister.add_payload.call_count == 1
        assert "http://perdu.com/secret" in persister.add_payload.call_args_list[0][1]["info"]


@pytest.mark.asyncio
@respx.mock
async def test_catch_all_redirection():
    # The server redirects every unknown path to the same location (catch-all).
    # Such redirections must not be reported as discovered pages.
    respx.get("http://perdu.com/").mock(return_value=httpx.Response(200, text="Default page"))
    # A real page that redirects somewhere specific
    respx.get("http://perdu.com/login").mock(
        return_value=httpx.Response(302, headers={"Location": "http://perdu.com/dashboard"})
    )
    # Everything else is redirected to the generic error page
    respx.get(url__regex=r"http://perdu\.com/.*").mock(
        return_value=httpx.Response(302, headers={"Location": "http://perdu.com/not-found"})
    )

    persister = AsyncMock()
    request = Request("http://perdu.com/")
    request.path_id = 1
    persister.get_links = AsyncIterator([(request, None)])

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2, "tasks": 20}

        files = {"wordlist.txt": "nawak\nlogin\nanother"}
        with mock.patch("builtins.open", get_mock_open(files)):
            module = ModuleBuster(crawler, persister, options, crawler_configuration)
            module.DATA_DIR = ""
            module.PATHS_FILE = "wordlist.txt"
            module.do_get = True
            await module.attack(request)

        # Only /login (redirected to a different location) should be reported
        assert persister.add_payload.call_count == 1
        assert "http://perdu.com/login" in persister.add_payload.call_args_list[0][1]["info"]


@pytest.mark.asyncio
@respx.mock
async def test_server_errors_are_not_reported():
    # Under the load of the wordlist the target starts answering 503 (rate limiting).
    # A 5xx must never be reported as a discovered page, unlike genuine 200/redirects.
    respx.get("http://perdu.com/").mock(return_value=httpx.Response(200, text="Default page"))
    # A real page
    respx.get("http://perdu.com/real").mock(return_value=httpx.Response(200, text="Actual content"))
    # A real page redirecting to a specific location
    respx.get("http://perdu.com/login").mock(
        return_value=httpx.Response(302, headers={"Location": "http://perdu.com/auth"})
    )
    # Candidates the server chokes on once the scan ramps up
    respx.get("http://perdu.com/overloaded").mock(return_value=httpx.Response(503, text="Service Unavailable"))
    respx.get("http://perdu.com/another").mock(return_value=httpx.Response(503, text="Service Unavailable"))
    # The improbable baseline probe is sent first and still gets a clean 404,
    # so it does not match the 503 candidates (that is what made the bug slip through).
    respx.get(url__regex=r"http://perdu\.com/.*").mock(return_value=httpx.Response(404))

    persister = AsyncMock()
    request = Request("http://perdu.com/")
    request.path_id = 1
    persister.get_links = AsyncIterator([(request, None)])

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2, "tasks": 20}

        files = {"wordlist.txt": "overloaded\nreal\nlogin\nanother"}
        with mock.patch("builtins.open", get_mock_open(files)):
            module = ModuleBuster(crawler, persister, options, crawler_configuration)
            module.DATA_DIR = ""
            module.PATHS_FILE = "wordlist.txt"
            module.do_get = True
            await module.attack(request)

        # Only /real (200) and /login (302 to a specific location) are reported;
        # the 503 candidates must be discarded.
        reported = {call[1]["request"].url for call in persister.add_payload.call_args_list}
        assert reported == {"http://perdu.com/real", "http://perdu.com/login"}


@pytest.mark.asyncio
@respx.mock
async def test_rate_limiting_warning_emitted_once(caplog):
    # A storm of 503 responses must trigger a single warning per host, not one per response.
    caplog.set_level(logging.INFO)
    respx.get("http://perdu.com/").mock(return_value=httpx.Response(200, text="Default page"))
    respx.get(url__regex=r"http://perdu\.com/.*").mock(return_value=httpx.Response(503, text="nope"))

    persister = AsyncMock()
    request = Request("http://perdu.com/")
    request.path_id = 1
    persister.get_links = AsyncIterator([(request, None)])

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2, "tasks": 20}

        files = {"wordlist.txt": "\n".join(f"path{i}" for i in range(30))}
        with mock.patch("builtins.open", get_mock_open(files)):
            module = ModuleBuster(crawler, persister, options, crawler_configuration)
            module.DATA_DIR = ""
            module.PATHS_FILE = "wordlist.txt"
            module.do_get = True
            await module.attack(request)

        # No path reported despite the flood of 503...
        assert persister.add_payload.call_count == 0
        # ...and exactly one rate-limiting warning for the host
        warnings = [rec.message for rec in caplog.records if "rate limiting or overload" in rec.message]
        assert len(warnings) == 1
        assert "perdu.com" in warnings[0]


async def delayed_response():
    await sleep(15)
    return httpx.Response(200, text="Hello there")
