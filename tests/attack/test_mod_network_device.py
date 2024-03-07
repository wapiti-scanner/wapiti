from asyncio import Event
from unittest.mock import AsyncMock

import httpx
from httpx import RequestError
import respx
import pytest

from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_network_device import ModuleNetworkDevice
from wapitiCore.attack.network_devices.mod_forti import ModuleForti


@pytest.mark.asyncio
@respx.mock
async def test_no_net_device():
    # Test no network device detected
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


@pytest.mark.asyncio
@respx.mock
async def test_detect_fortimanager():
    respx.get("http://perdu.com/p/login/").mock(
        return_value=httpx.Response(
            200,
            content='<html><head><title>Vous Perdu ?</title></head><body><h1>Perdu sur Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            <div class="sign-in-header" style="visibility: hidden"><span class="platform">FortiManager-3000G</span>'
                    '</body></html>'
        )
    )
    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            200,
            content='<html><head><title>Vous Perdu ?</title></head><body><h1>Perdu sur Internet ?</h1> \
                <h2>Pas de panique, on va vous aider</h2> </body></html>'
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
            '{"name": "FortiManager", "version": "", "categories": ["Network Equipment"], "groups": ["Content"]}'
        )


@pytest.mark.asyncio
@respx.mock
async def test_detect_ssl_vpn():
    respx.get("http://perdu.com/remote/login?lang=en").mock(
        return_value=httpx.Response(
            200,
            content='<html><head><title>Login</title></head><body><h1>Perdu sur Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> '
        )
    )

    respx.get("http://perdu.com/remote/fgt_lang?lang=fr").mock(
        return_value=httpx.Response(
            200,
            content='<html><head><title>Vous Perdu ?</title></head><body><h1>Perdu sur Internet ?</h1> \
                <h2>Pas de panique, on va vous aider</h2> </body></html>'
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
            '{"name": "Fortinet SSL-VPN", "version": "", "categories": ["Network Equipment"], "groups": ["Content"]}'
        )


@pytest.mark.asyncio
@respx.mock
async def test_detect_fortinet():
    respx.get("http://perdu.com/login/?next=/").mock(
        return_value=httpx.Response(
            200,
            content='<html><head><title>Login</title></head><body><h1>Perdu sur Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> '
        )
    )
    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            200,
            content='<html><head><title>Vous Perdu ?</title></head><body><h1>Perdu sur Internet ?</h1> \
                <h2>Pas de panique, on va vous aider</h2> </body></html>'
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
            '{"name": "Fortinet", "version": "", "categories": ["Network Equipment"], "groups": ["Content"]}'
        )


@pytest.mark.asyncio
@respx.mock
async def test_detect_fortiportal_from_title():
    respx.get("http://perdu.com/fpc/app/login").mock(
        return_value=httpx.Response(
            200,
            content='<html><head><title>FortiPortal</title></head><body><h1>Perdu sur Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> '
        )
    )
    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            200,
            content='<html><head><title>Vous Perdu ?</title></head><body><h1>Perdu sur Internet ?</h1> \
                <h2>Pas de panique, on va vous aider</h2> </body></html>'
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
            '{"name": "FortiPortal", "version": "", "categories": ["Network Equipment"], "groups": ["Content"]}'
        )


@pytest.mark.asyncio
@respx.mock
async def test_detect_fortimail():
    respx.get("http://perdu.com/admin/").mock(
        return_value=httpx.Response(
            200,
            content='<html><head><title>FortiMail</title><meta name="FortiMail" content="width=device-width, initial-scale=1">\
            </head><body><h1>Perdu sur Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> '
        )
    )
    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            200,
            content='<html><head><title>Vous Perdu ?</title></head><body><h1>Perdu sur Internet ?</h1> \
                <h2>Pas de panique, on va vous aider</h2> </body></html>'
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
            '{"name": "FortiMail", "version": "", "categories": ["Network Equipment"], "groups": ["Content"]}'
        )


@pytest.mark.asyncio
@respx.mock
async def test_raise_on_request_error():
    """Tests that a RequestError is raised when calling the module with wrong URL."""

    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            200,
            content='<html><head><title>Vous Perdu ?</title></head><body><h1>Perdu sur Internet ?</h1> \
                    <h2>Pas de panique, on va vous aider</h2> </body></html>'
        )
    )

    respx.get(url__regex=r"http://perdu.com/.*").mock(side_effect=RequestError("RequestError occurred: [Errno -2] Name or service not known"))

    persister = AsyncMock()

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2, "tasks": 20}

        module = ModuleForti(crawler, persister, options, Event(), crawler_configuration)

        with pytest.raises(RequestError) as exc_info:
            await module.check_forti("http://perdu.com/")

        assert exc_info.value.args[0] == "RequestError occurred: [Errno -2] Name or service not known"
