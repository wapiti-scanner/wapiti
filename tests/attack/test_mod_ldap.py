from subprocess import Popen
import os
import sys
from time import sleep
from asyncio import Event, sleep as Sleep
from unittest.mock import AsyncMock

import pytest
import respx
import httpx

from wapitiCore.attack.attack import Parameter, ParameterSituation, random_string
from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_ldap import (
    ModuleLdap, string_without_payload, find_ldap_error, PayloadInfo, group_mutations_per_context
)


@pytest.fixture(autouse=True)
def run_around_tests():
    base_dir = os.path.dirname(sys.modules["wapitiCore"].__file__)
    test_directory = os.path.join(base_dir, "..", "tests/data/")

    proc = Popen(["php", "-S", "127.0.0.1:65083", "-a", "-t", test_directory])
    sleep(.5)
    yield
    proc.terminate()


def test_string_without_payload():
    assert string_without_payload("Hello <there>", "<there>") == "Hello "
    assert string_without_payload("Hello &lt;there&gt;", "<there>") == "Hello "


def test_find_ldap_error():
    assert find_ldap_error("Look, The syntax is invalid dude") == "The syntax is invalid"
    assert find_ldap_error("Hey dude, where is my car?") is None


def test_group_mutations_per_context():
    items = [
        (Request("http://a/1"), PayloadInfo("t", "ctx1", False)),
        (Request("http://a/4"), PayloadInfo("u", "ctx2", False)),
        (Request("http://a/5"), PayloadInfo("u", "ctx3", False)),
        (Request("http://a/2"), PayloadInfo("w", "ctx1", False)),
        (Request("http://a/6"), PayloadInfo("x", "ctx3", False)),
        (Request("http://a/3"), PayloadInfo("y", "ctx1", True)),
        (Request("http://a/7"), PayloadInfo("z", "ctx3", False)),
    ]

    groups = group_mutations_per_context(items)
    assert list(groups.keys()) == ["ctx1", "ctx2", "ctx3"]
    assert len(groups["ctx1"]) == 3
    assert len(groups["ctx2"]) == 1
    assert len(groups["ctx3"]) == 3


@pytest.mark.asyncio
@respx.mock
async def test_whole_stuff():
    # Test attacking all kind of parameter without crashing
    respx.get(url__regex=r"http://perdu\.com/.*").mock(httpx.Response(200, text="Hello there"))
    respx.post(url__regex=r"http://perdu\.com/.*").mock(httpx.Response(200, text="Hello there"))

    persister = AsyncMock()
    all_requests = []

    request = Request("http://perdu.com/")
    request.path_id = 1
    all_requests.append(request)

    request = Request("http://perdu.com/?foo=bar")
    request.path_id = 2
    all_requests.append(request)

    request = Request(
        "http://perdu.com/?foo=bar",
        post_params=[["a", "b"]],
        file_params=[["file", ("calendar.xml", b"<xml>Hello there</xml", "application/xml")]]
    )
    request.path_id = 3
    all_requests.append(request)

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleLdap(crawler, persister, options, Event(), crawler_configuration)
        module.do_post = True
        for request in all_requests:
            await module.attack(request)

        assert True


def random_response(_):
    random_text = random_string()
    return httpx.Response(200, text=random_text)


@pytest.mark.asyncio
@respx.mock
async def test_random_responses():
    # Test for false positives prevention
    # Here pages are returning random content
    respx.get(url__regex=r"http://perdu\.com/.*").mock(side_effect=random_response)
    respx.post(url__regex=r"http://perdu\.com/.*").mock(side_effect=random_response)

    persister = AsyncMock()
    all_requests = []

    request = Request("http://perdu.com/")
    request.path_id = 1
    all_requests.append(request)

    request = Request("http://perdu.com/?foo=bar")
    request.path_id = 2
    all_requests.append(request)

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleLdap(crawler, persister, options, Event(), crawler_configuration)
        for request in all_requests:
            await module.attack(request)

        persister.add_payload.assert_not_called()
