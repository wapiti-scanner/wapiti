import os
import sys
from os.path import join as path_join
from asyncio import Event
from unittest.mock import AsyncMock

import httpx
import respx
import pytest

from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_prestashop_enum import ModulePrestashopEnum


# Test no PrestaShop detected
@pytest.mark.asyncio
@respx.mock
async def test_no_prestashop():
    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong></body></html>"
        )
    )

    # Response to check that we have no more false positives

    respx.get(url__regex=r"http://perdu.com/.*?").mock(return_value=httpx.Response(404))

    persister = AsyncMock()

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2, "tasks": 20}

        module = ModulePrestashopEnum(crawler, persister, options, Event(), crawler_configuration)

        await module.attack(request)

        assert not persister.add_payload.call_count


@pytest.mark.asyncio
@respx.mock
async def test_version_detected():

    base_dir = os.path.dirname(sys.modules["wapitiCore"].__file__)
    test_directory = os.path.join(base_dir, "..", "tests/data/prestashop/")
    prestashop_file = "admin.js"

    with open(path_join(test_directory, prestashop_file), errors="ignore") as prestashop:
        data = prestashop.read()

    # Response to tell that PrestaShop is used
    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            200,
            content="<html><head><title>Helo</title>\
            </head><body>This website uses Prestashop, prestashop = []</body></html>")
        )

    # Response for admin.js
    respx.get("http://perdu.com/js/admin.js")\
        .mock(return_value=httpx.Response(200, text=data))

    respx.get(url__regex=r"http://perdu.com/.*?").mock(return_value=httpx.Response(404))

    persister = AsyncMock()

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2, "tasks": 20}

        module = ModulePrestashopEnum(crawler, persister, options, Event(), crawler_configuration)

        await module.attack(request)

        assert persister.add_payload.call_count == 2
        assert persister.add_payload.call_args_list[0][1]["module"] == "prestashop_enum"
        assert persister.add_payload.call_args_list[0][1]["category"] == "Fingerprint web application framework"
        assert persister.add_payload.call_args_list[0][1]["info"] == (
            '{"name": "PrestaShop", "versions": ["1.6.0.5"], "categories": ["CMS PrestaShop"], "groups": ["Content"]}'
        )
        assert persister.add_payload.call_args_list[1][1]["module"] == "prestashop_enum"
        assert persister.add_payload.call_args_list[1][1]["category"] == "Fingerprint web technology"
        assert persister.add_payload.call_args_list[1][1]["info"] == (
            '{"name": "PrestaShop", "versions": ["1.6.0.5"], "categories": ["CMS PrestaShop"], "groups": ["Content"]}'
        )


@pytest.mark.asyncio
@respx.mock
async def test_multi_versions_detected():

    base_dir = os.path.dirname(sys.modules["wapitiCore"].__file__)
    test_directory = os.path.join(base_dir, "..", "tests/data/prestashop/")
    helpsite_file = "theme.css"

    with open(path_join(test_directory, helpsite_file), errors="ignore") as helpsite:
        data = helpsite.read()

    # Response to tell that PrestaShop is used
    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            200,
            content="This website use PrestaShop, prestashop = []")
    )

    # Response for  theme.css
    respx.get("http://perdu.com/themes/classic/assets/css/theme.css")\
        .mock(return_value=httpx.Response(200, text=data))

    respx.get(url__regex=r"http://perdu.com/.*?").mock(return_value=httpx.Response(404))

    persister = AsyncMock()

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2, "tasks": 20}

        module = ModulePrestashopEnum(crawler, persister, options, Event(), crawler_configuration)

        await module.attack(request)

        assert persister.add_payload.call_count == 2
        assert persister.add_payload.call_args_list[0][1]["info"] == (
            '{"name": "PrestaShop", "versions": ["1.7.7.6", "1.7.7.7", "1.7.7.8"], "categories": ["CMS PrestaShop"], "groups": ["Content"]}'
        )
        assert persister.add_payload.call_args_list[0][1]["info"] == (
            '{"name": "PrestaShop", "versions": ["1.7.7.6", "1.7.7.7", "1.7.7.8"], "categories": ["CMS PrestaShop"], "groups": ["Content"]}'
        )


@pytest.mark.asyncio
@respx.mock
async def test_version_not_detected():

    base_dir = os.path.dirname(sys.modules["wapitiCore"].__file__)
    test_directory = os.path.join(base_dir, "..", "tests/data/prestashop/")
    prestashop_edited = "theme_edited.css"

    with open(path_join(test_directory, prestashop_edited), errors="ignore") as prestashop:
        data = prestashop.read()

    # Response to tell that PrestaShop is used
    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            200,
            content="This website use Prestashop prestashop = []")
    )

    # Response for edited changelog.txt
    respx.get("http://perdu.com/themes/classic/assets/css/theme.css").mock(return_value=httpx.Response(200, text=data))

    respx.get(url__regex=r"http://perdu.com/.*?").mock(return_value=httpx.Response(404))

    persister = AsyncMock()

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2, "tasks": 20}

        module = ModulePrestashopEnum(crawler, persister, options, Event(), crawler_configuration)

        await module.attack(request)

        assert persister.add_payload.call_count == 1
        assert persister.add_payload.call_args_list[0][1]["info"] == (
            '{"name": "PrestaShop", "versions": [], "categories": ["CMS PrestaShop"], "groups": ["Content"]}'
        )
