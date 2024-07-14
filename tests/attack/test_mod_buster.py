from unittest import mock
from unittest.mock import AsyncMock
from asyncio import Event, sleep

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
            module = ModuleBuster(crawler, persister, options, Event(), crawler_configuration)
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


async def delayed_response():
    await sleep(15)
    return httpx.Response(200, text="Hello there")
