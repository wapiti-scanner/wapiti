from asyncio import Event
from fnmatch import fnmatch
from hashlib import md5
from unittest.mock import AsyncMock

import pytest
import respx
import httpx

from wapitiCore.attack.attack import random_string
from wapitiCore.language.vulnerability import CRITICAL_LEVEL, HIGH_LEVEL
from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_ldap import (
    ModuleLdap, string_without_payload, find_ldap_error, PayloadInfo, group_mutations_per_context
)


def test_string_without_payload():
    assert string_without_payload("Hello <there>", "<there>") == "Hello "
    assert string_without_payload("Hello &lt;there&gt;", "<there>") == "Hello "
    assert string_without_payload("Hello+%3Cthere%3E", " <there>") == "Hello"
    assert string_without_payload("Hello%20%3Cthere%3E", " <there>") == "Hello"


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


def web_ldap_mock(request):
    users = ["John", "Karlee", "Rufus"]
    username = request.url.params.get("user")
    password = request.url.params.get("password")
    if ")\0" in username:
        password = None
        username = username.split(")\0")[0]

    for user in users:
        if fnmatch(user, username):
            if password is None:
                return httpx.Response(200, text=f"Welcome {username}")
            else:
                return httpx.Response(200, text="Bad password")

    if password is not None and ")\0" in password:
        return httpx.Response(500, text="Internal Server Error")

    return httpx.Response(200, text="No such user")


@pytest.mark.asyncio
@respx.mock
async def test_vulnerabilities():
    respx.get(url__regex=r"http://perdu\.com/vuln\?.*").mock(side_effect=web_ldap_mock)
    respx.get(url__regex=r"http://perdu\.com/").mock(return_value=httpx.Response(200, text="Hello there"))

    persister = AsyncMock()
    all_requests = []

    request = Request("http://perdu.com/")
    request.path_id = 1
    all_requests.append(request)

    request = Request("http://perdu.com/vuln?user=foo&password=bar")
    request.path_id = 2
    all_requests.append(request)

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleLdap(crawler, persister, options, Event(), crawler_configuration)
        for request in all_requests:
            await module.attack(request)

        assert persister.add_payload.call_count == 2
        assert persister.add_payload.call_args_list[0][1]["module"] == "ldap"
        assert persister.add_payload.call_args_list[0][1]["category"] == "LDAP Injection"
        assert persister.add_payload.call_args_list[0][1]["level"] == CRITICAL_LEVEL
        assert persister.add_payload.call_args_list[0][1]["request"].url == (
            "http://perdu.com/vuln?user=%2A%29%29%00nosuchvalue&password=bar"
        )
        assert persister.add_payload.call_args_list[0][1]["info"] == (
            "LDAP Injection via injection in the parameter user"
        )

        assert persister.add_payload.call_args_list[1][1]["module"] == "ldap"
        assert persister.add_payload.call_args_list[1][1]["category"] == "Internal Server Error"
        assert persister.add_payload.call_args_list[1][1]["level"] == HIGH_LEVEL
        assert persister.add_payload.call_args_list[1][1]["request"].url == (
            "http://perdu.com/vuln?user=foo&password=nosuchvalue%29%29%00"
        )
        assert persister.add_payload.call_args_list[1][1]["info"] == (
            "The server responded with a 500 HTTP error code while attempting "
            "to inject a payload in the parameter password"
        )

    assert module.network_errors == 0


@pytest.mark.asyncio
@respx.mock
async def test_is_page_dynamic():
    respx.get("http://perdu.com/").mock(side_effect=httpx.RequestError("error"))
    respx.get("http://perdu.com/hello").mock(return_value=httpx.Response(200, text="Hello there"))

    persister = AsyncMock()

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleLdap(crawler, persister, options, Event(), crawler_configuration)
        assert not await module.is_page_dynamic(
            Request("http://perdu.com/"),
            PayloadInfo("", "", True),
            "hash"
        )
        assert module.network_errors == 1

        assert not await module.is_page_dynamic(
            Request("http://perdu.com/hello"),
            PayloadInfo("", "", True),
            md5(b"Hello there").hexdigest(),
        )

        assert await module.is_page_dynamic(
            Request("http://perdu.com/hello"),
            PayloadInfo("", "", True),
            "yolo",
        )
