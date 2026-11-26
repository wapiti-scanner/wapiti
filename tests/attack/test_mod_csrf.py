from subprocess import Popen
import os
import sys
from time import sleep
from unittest.mock import AsyncMock
from urllib.parse import parse_qsl

import httpx
import pytest
import respx

from wapitiCore.net import Request, Response
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.attack.mod_csrf import ModuleCsrf


@pytest.fixture()
def run_around_tests():
    base_dir = os.path.dirname(sys.modules["wapitiCore"].__file__)
    test_directory = os.path.join(base_dir, "..", "tests/data/csrf/")

    proc = Popen(["php", "-S", "127.0.0.1:65086", "-a", "-t", test_directory])  # pylint: disable=consider-using-with
    sleep(.5)
    yield
    proc.terminate()


@pytest.mark.usefixtures("run_around_tests")
@pytest.mark.asyncio
async def test_csrf_cases():
    persister = AsyncMock()
    all_requests = []

    response = Response(
        httpx.Response(status_code=200),
        url="http://127.0.0.1:65086/"
    )

    request = Request("http://127.0.0.1:65086/")
    request.path_id = 1
    all_requests.append((request, response))

    request = Request(
        "http://127.0.0.1:65086/",
        method="POST",
        post_params=[["email", "wapiti2021@mailinator.com"], ["xsrf_token", "weak"]],
    )
    request.path_id = 2
    all_requests.append((request, response))

    request = Request(
        "http://127.0.0.1:65086/?check=true",
        method="POST",
        post_params=[["email", "wapiti2021@mailinator.com"], ["xsrf_token", "weak"]],
    )
    request.path_id = 3
    all_requests.append((request, response))

    request = Request(
        "http://127.0.0.1:65086/?check=true",
        method="POST",
        post_params=[["name", "Obiwan"]],
    )
    request.path_id = 4
    all_requests.append((request, response))

    response = Response(
        httpx.Response(status_code=200, headers={"x-csrf-token": "testestestest"}),
        url="http://127.0.0.1:65086/"
    )

    request = Request("http://127.0.0.1:65086/", method="POST")
    request.path_id = 5
    all_requests.append((request, response))

    response = Response(
        httpx.Response(status_code=200),
        url="http://127.0.0.1:65086/"
    )

    request = Request(
        "http://127.0.0.1:65086/",
        method="POST",
        post_params=[["name", "Obiwan"]],
        headers={"x-csrf-token": "testestestest"}
    )
    request.path_id = 6
    all_requests.append((request, response))

    crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:65086/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 1}

        module = ModuleCsrf(crawler, persister, options, crawler_configuration)
        module.do_post = True
        for request, response in all_requests:
            if await module.must_attack(request, response):
                await module.attack(request, response)
            else:
                # Not attacked because of GET verb
                assert request.path_id == 1

        vulnerabilities = set()
        for call in persister.add_payload.call_args_list:
            vulnerabilities.add(call[1]["info"])

        assert vulnerabilities == {
            "CSRF token 'xsrf_token' is not properly checked in backend",
            "CSRF token 'xsrf_token' might be easy to predict",
            "Lack of anti CSRF token",
            "CSRF token 'x-csrf-token' is not properly checked in backend",
        }


@pytest.mark.parametrize(
    ("param_name", "expected_csrf_string"),
    [
        ("csrf_token", "csrf_token"),
        ("form[csrf_token]", "form[csrf_token]"),
        ("form[_token]", "form[_token]"),
        ("form[profile][_token]", "form[profile][_token]"),
        ("form[CSRF_TOKEN]", "form[CSRF_TOKEN]"),
    ],
)
@pytest.mark.asyncio
async def test_csrf_present_recognizes_flat_and_bracketed_fields(param_name, expected_csrf_string):
    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        module = ModuleCsrf(crawler, AsyncMock(), {"timeout": 10, "level": 1}, crawler_configuration)
        request = Request(
            "http://perdu.com/form",
            method="POST",
            post_params=[["form[loremipsum]", "hello"], [param_name, "a1b2c3d4e5f6"]],
        )
        response = Response(httpx.Response(status_code=200), url="http://perdu.com/form")

        assert module.is_csrf_present(request, response) == "a1b2c3d4e5f6"
        assert module.csrf_string == expected_csrf_string


@pytest.mark.parametrize(
    "param_name",
    [
        "form[loremipsum]",
        "form[my_csrf_token]",
        "token[name]",
        "token[]",
        "[csrf_token]",
        "username",
    ],
)
@pytest.mark.asyncio
async def test_csrf_present_ignores_non_token_fields(param_name):
    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        module = ModuleCsrf(crawler, AsyncMock(), {"timeout": 10, "level": 1}, crawler_configuration)
        request = Request(
            "http://perdu.com/form",
            method="POST",
            post_params=[[param_name, "a1b2c3d4e5f6"]],
        )
        response = Response(httpx.Response(status_code=200), url="http://perdu.com/form")

        assert module.is_csrf_present(request, response) is None
        assert module.csrf_string is None


@respx.mock
@pytest.mark.asyncio
async def test_csrf_attack_bracketed_fields():
    mutated_requests = []

    def validated_endpoint(req: httpx.Request) -> httpx.Response:
        params = dict(parse_qsl(req.content.decode()))
        for token_key in ("csrf_token", "form[csrf_token]", "form[_token]"):
            if token_key in params:
                if params[token_key] == "a1b2c3d4e5f6":
                    return httpx.Response(200, text="OK")
                mutated_requests.append(params)
                return httpx.Response(403, text="Invalid CSRF token")
        return httpx.Response(200, text="OK")

    respx.post("http://perdu.com/form").mock(side_effect=validated_endpoint)
    respx.post("http://perdu.com/unchecked").mock(return_value=httpx.Response(200, text="OK"))

    persister = AsyncMock()
    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
    response = Response(httpx.Response(status_code=200), url="http://perdu.com/form")

    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        module = ModuleCsrf(crawler, persister, {"timeout": 10, "level": 1}, crawler_configuration)

        # 1. Flat token validated by backend -> no finding
        await module.attack(
            Request("http://perdu.com/form", method="POST", post_params=[["csrf_token", "a1b2c3d4e5f6"]]),
            response,
        )
        # 2. Bracketed form[csrf_token] validated by backend -> no finding, original key mutated
        await module.attack(
            Request(
                "http://perdu.com/form",
                method="POST",
                post_params=[["form[loremipsum]", "hello"], ["form[csrf_token]", "a1b2c3d4e5f6"]],
            ),
            response,
        )
        # 3. Bracketed form[_token] validated by backend -> no finding
        await module.attack(
            Request(
                "http://perdu.com/form",
                method="POST",
                post_params=[["form[loremipsum]", "hello"], ["form[_token]", "a1b2c3d4e5f6"]],
            ),
            response,
        )
        assert persister.add_payload.call_count == 0
        assert {"form[loremipsum]": "hello", "form[csrf_token]": "wapiti"} in mutated_requests

        # 4. Unchecked bracketed token -> reports original full parameter name
        await module.attack(
            Request(
                "http://perdu.com/unchecked",
                method="POST",
                post_params=[["form[loremipsum]", "hello"], ["form[csrf_token]", "a1b2c3d4e5f6"]],
            ),
            Response(httpx.Response(status_code=200), url="http://perdu.com/unchecked"),
        )
        # 5. Ordinary bracketed field without token -> missing token warning
        await module.attack(
            Request("http://perdu.com/form", method="POST", post_params=[["form[loremipsum]", "hello"]]),
            response,
        )
        # 6. Plain form without token -> missing token warning
        await module.attack(
            Request("http://perdu.com/form", method="POST", post_params=[["username", "alice"]]),
            response,
        )

    infos = [call.kwargs["info"] for call in persister.add_payload.call_args_list]
    assert infos == [
        "CSRF token 'form[csrf_token]' is not properly checked in backend",
        "Lack of anti CSRF token",
        "Lack of anti CSRF token",
    ]
