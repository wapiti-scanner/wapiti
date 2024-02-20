from asyncio import Event
from unittest.mock import AsyncMock

import httpx
import respx
import pytest

from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_network_device import ModuleNetworkDevice


@pytest.mark.asyncio
@respx.mock
async def test_no_ubika():
    # Test no UBIKA detected
    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            200,
            content="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong></body></html>"
        )
    )

    respx.get(url__regex=r"http://perdu.com/.*?").mock(return_value=httpx.Response(404))

    persister = AsyncMock()

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2, "tasks": 20}

        module = ModuleNetworkDevice(crawler, persister, options, Event(), crawler_configuration)

        await module.attack(request)

        assert not persister.add_payload.call_count

@pytest.mark.asyncio
@respx.mock
async def test_ubika_without_version():
    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            200,
            content="<html><head><title>Vous Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong></body></html>"
        )
    )
    respx.get("http://perdu.com/app/monitor/").mock(
        return_value=httpx.Response(
            200,
            content="<html><head><title>UBIKA WAAP GATEWAY</title></head><body><h1>Perdu sur l'Internet ?</h1> \
                <h2>Pas de panique, on va vous aider</h2> \
                <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong></body></html>"
        )
    )
    respx.get(url__regex=r"http://perdu.com/.*?").mock(return_value=httpx.Response(404))

    persister = AsyncMock()

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2, "tasks": 20}

        module = ModuleNetworkDevice(crawler, persister, options, Event(), crawler_configuration)

        await module.attack(request)

        assert persister.add_payload.call_count == 1
        assert persister.add_payload.call_args_list[0][1]["info"] == (
            '{"name": "UBIKA WAAP", "version": "", "categories": ["Network Equipment"], "groups": ["Content"]}'
        )

@pytest.mark.asyncio
@respx.mock
async def test_ubika_with_version():
    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            200,
            content="<html><head><title>Vous Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong></body></html>"
        )
    )
    respx.get("http://perdu.com/app/monitor/").mock(
        return_value=httpx.Response(
            200,
            content="<html><head><title>UBIKA WAAP GATEWAY</title></head><body><h1>Perdu sur l'Internet ?</h1> \
                <h2>Pas de panique, on va vous aider</h2> \
                <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong></body></html>"
        )
    )

    respx.get("http://perdu.com/app/monitor/api/info/product").mock(
        return_value=httpx.Response(
            200,
            content='{"result":{"api":{"version":"1.0","logLevel":"info"},\
            "appliance":{"name":"Management","role":"manager","ip":"192.168.0.169","port":3002},\
            "product":{"version":"6.5.6"}},"_info":{"apiVersion":"1.0","serverTimestamp":1708417838114,\
            "responseTime":"0s","responseStatus":200}}'
        )
    )

    respx.get(url__regex=r"http://perdu.com/.*?").mock(return_value=httpx.Response(404))

    persister = AsyncMock()

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2, "tasks": 20}

        module = ModuleNetworkDevice(crawler, persister, options, Event(), crawler_configuration)

        await module.attack(request)

        assert persister.add_payload.call_count == 1
        assert persister.add_payload.call_args_list[0][1]["category"] == "Fingerprint web technology"
        assert persister.add_payload.call_args_list[0][1]["info"] == (
            '{"name": "UBIKA WAAP", "version": "6.5.6", "categories": ["Network Equipment"], "groups": ["Content"]}'
        )
