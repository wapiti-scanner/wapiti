import asyncio
import os
from asyncio import Event
from unittest.mock import AsyncMock
from httpx import Response as HttpxResponse

import pytest
import respx

from wapitiCore.attack.mod_spring4shell import ModuleSpring4Shell
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net import Request

payload = "class.module.classLoader[wapiti]=wapiti"

@pytest.mark.asyncio
@respx.mock
async def test_detect_spring4shell():

    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE") or "/home"
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1
    options = {"timeout": 10, "level": 2}

    respx.get("http://perdu.com/").mock(return_value=HttpxResponse(200, request=request))
    respx.post("http://perdu.com/").mock(return_value=HttpxResponse(500, request=request))

    crawler_configuration = CrawlerConfiguration(request)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:

        module = ModuleSpring4Shell(crawler, persister, options, Event(), crawler_configuration)

        assert await module._check_spring4shell("GET", request, payload) == False

        future_url_vulnerability = asyncio.Future()
        future_url_vulnerability.set_result(None)

        assert await module._attack_spring4shell_url(request) == None



@pytest.mark.asyncio
@respx.mock
async def test_detect_spring4shell_get():

    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE") or "/home"
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1
    options = {"timeout": 10, "level": 2}

    respx.get("http://perdu.com/?class.module.classLoader[wapiti]=wapiti").mock(return_value=HttpxResponse(500, request=request))
    respx.post("http://perdu.com/").mock(return_value=HttpxResponse(200, request=request))
    respx.get("http://perdu.com/").mock(return_value=HttpxResponse(200, request=request))

    crawler_configuration = CrawlerConfiguration(request)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:

        module = ModuleSpring4Shell(crawler, persister, options, Event(), crawler_configuration)

        assert await module._check_spring4shell("GET", request, payload) == True
        assert await module._check_spring4shell("POST", request, payload) == False

@pytest.mark.asyncio
@respx.mock
async def test_no_spring4shell():

    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE") or "/home"
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1
    options = {"timeout": 10, "level": 2}

    respx.get("http://perdu.com/").mock(return_value=HttpxResponse(200, request=request))
    respx.post("http://perdu.com/").mock(return_value=HttpxResponse(200, request=request))

    crawler_configuration = CrawlerConfiguration(request)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:

        module = ModuleSpring4Shell(crawler, persister, options, Event(), crawler_configuration)

        assert await module._check_spring4shell("GET", request, payload) == False
        assert await module._check_spring4shell("POST", request, payload) == False