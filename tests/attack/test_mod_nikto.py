import os
from asyncio import Event
from itertools import chain
from unittest.mock import AsyncMock

import httpx
import respx
import pytest

from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_nikto import ModuleNikto


@pytest.mark.asyncio
@respx.mock
async def test_whole_stuff():
    # Test attacking all kind of parameter without crashing
    respx.route(host="raw.githubusercontent.com").pass_through()

    respx.get("http://perdu.com/cgi-bin/a1disp3.cgi?../../../../../../../../../../etc/passwd").mock(
        return_value=httpx.Response(200, text="root:0:0:")
    )

    respx.route(host="perdu.com").mock(
        return_value=httpx.Response(404, text="Not found")
    )

    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE") or "/home"
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1
    persister.get_links.return_value = chain([request])

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2, "tasks": 20}

        module = ModuleNikto(crawler, persister, options, Event(), crawler_configuration)
        module.do_get = True
        await module.attack(request)

        assert persister.add_payload.call_count == 1
        assert persister.add_payload.call_args_list[0][1]["module"] == "nikto"
        assert persister.add_payload.call_args_list[0][1]["category"] == "Potentially dangerous file"
        assert persister.add_payload.call_args_list[0][1]["request"].url == (
            "http://perdu.com/cgi-bin/a1disp3.cgi?..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd"
        )
        assert (
                   "This CGI allows attackers read arbitrary files on the host"
               ) in persister.add_payload.call_args_list[0][1]["info"]


@pytest.mark.asyncio
@respx.mock
async def test_false_positives():
    respx.route(host="raw.githubusercontent.com").pass_through()

    # This one trigger a match based on content
    respx.get("http://perdu.com/opendir.php?/etc/passwd").mock(
        return_value=httpx.Response(200, text="root:0:0:")
    )
    # A lot of cases will trigger because HTTP 200 is returned instead of 404 but false positive check should block them
    respx.route(host="perdu.com").mock(
        return_value=httpx.Response(200, text="Hello there")
    )

    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE") or "/home"
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    temp_nikto_db = os.path.join(persister.CONFIG_DIR, "temp_nikto_db")
    with open(temp_nikto_db, "w") as fd:
        fd.writelines(
            [
                "003270,539,d,/catinfo,GET,200,,,,,May be vulnerable to a buffer overflow. Request '/catinfo?',,\n",
                "003271,5407,a,/soap/servlet/soaprouter,GET,200,,,,,Oracle 9iAS SOAP components allow anonymous,,\n",
                "003272,543,7,/opendir.php?/etc/passwd,GET,root:,,,,,This PHP-Nuke CGI allows attackers to read,,\n"
            ]
        )

    request = Request("http://perdu.com/")
    request.path_id = 1
    persister.get_links.return_value = chain([request])

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2, "tasks": 20}

        module = ModuleNikto(crawler, persister, options, Event(), crawler_configuration)
        module.do_get = True
        module.NIKTO_DB = "temp_nikto_db"
        await module.attack(request)
        os.unlink(temp_nikto_db)

        assert persister.add_payload.call_count == 1
        assert persister.add_payload.call_args_list[0][1]["module"] == "nikto"
        assert persister.add_payload.call_args_list[0][1]["category"] == "Potentially dangerous file"
        assert persister.add_payload.call_args_list[0][1]["request"].url == (
            "http://perdu.com/opendir.php?%2Fetc%2Fpasswd"
        )
        assert (
                   "This PHP-Nuke CGI allows attackers to read"
               ) in persister.add_payload.call_args_list[0][1]["info"]
