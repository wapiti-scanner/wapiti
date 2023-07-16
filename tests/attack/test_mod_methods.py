from asyncio import Event
from unittest.mock import AsyncMock

import httpx
import respx
import pytest

from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net import Request, Response
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_methods import ModuleMethods


@pytest.mark.asyncio
@respx.mock
async def test_trivial():
    # Test the easiest cases
    mocking_links = [
        "http://perdu.com/",
        "http://perdu.com/dav/",
    ]

    # First case: We reply to OPTIONS with a short list of allowed methods
    respx.options(mocking_links[0]).mock(
        return_value=httpx.Response(200, text="Default page", headers={"Allow": "GET,POST,HEAD"})
    )

    # Here they are
    respx.get(mocking_links[0]).mock(
        return_value=httpx.Response(200, text="Body from GET option")
    )
    respx.post(mocking_links[0]).mock(
        return_value=httpx.Response(200, text="Body from GET option")
    )
    respx.head(mocking_links[0]).mock(
        return_value=httpx.Response(200, text="")
    )

    # Second case: more HTTP methods possible
    respx.options(mocking_links[1]).mock(
        # Method OPTIONS that discover the other methods
        return_value=httpx.Response(200, text="Private section", headers={"Allow": "GET,POST,HEAD,PUT,DELETE"})
    )

    # Not interesting
    respx.head(mocking_links[1]).mock(
        return_value=httpx.Response(200, text="")
    )
    # Used as reference for comparison
    respx.get(mocking_links[1]).mock(
        return_value=httpx.Response(200, text="Body from GET option")
    )
    # Same as reference
    respx.post(mocking_links[1]).mock(
        return_value=httpx.Response(200, text="Body from GET option")
    )
    # Should be detected
    respx.put(mocking_links[1]).mock(
        return_value=httpx.Response(500, text="Body from PUT method")
    )
    # Same as reference
    respx.delete(mocking_links[1]).mock(
        return_value=httpx.Response(200, text="Body from GET option")
    )

    persister = AsyncMock()
    all_requests = []

    for i, link in enumerate(mocking_links):
        request = Request(link)
        request.path_id = i+1
        # we simulate the get response
        response = Response(
            httpx.Response(status_code=200, text="Body from GET option"),
            url=link
        )
        all_requests.append((request, response))

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)

    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleMethods(crawler, persister, options, Event(), crawler_configuration)
        module.do_get = True
        for request, response in all_requests:
            await module.attack(request, response)

        assert persister.add_payload.call_count == 2
        assert "Possible interesting methods (using OPTIONS) on http://perdu.com/: OPTIONS (200)" == (
            persister.add_payload.call_args_list[0][1]["info"]
        )
        assert mocking_links[0] == persister.add_payload.call_args_list[0][1]["request"].url

        assert "Possible interesting methods (using OPTIONS) on http://perdu.com/dav/: OPTIONS (200) PUT (500)" == (
            persister.add_payload.call_args_list[1][1]["info"]
        )
        assert mocking_links[1] == persister.add_payload.call_args_list[1][1]["request"].url

        # OPTIONS,GET,POST,HEAD then OPTIONS,GET,POST,HEAD,PUT,DELETE
        assert len(respx.calls) == 10


@pytest.mark.asyncio
@respx.mock
async def test_advanced():
    # Test more advanced and complex cases
    # Below, link to test the module in the following cases:
    # - Not allowed method
    # - Same server code but different body
    # - Different server code but same body
    mocking_link = "http://perdu.com/dummy/"

    respx.options(mocking_link).mock(
        # Method OPTIONS that discover the other methods
        return_value=httpx.Response(
            200,
            text="Body from OPTIONS method",
            headers={"Allow": "GET,POST,HEAD,PUT,DELETE,PATCH"}
        )
    )
    respx.head(mocking_link).mock(
        # Method GET that serve as a reference
        return_value=httpx.Response(200, text="")
    )
    respx.get(mocking_link).mock(
        # Method GET that serve as a reference
        return_value=httpx.Response(200, text="Body from GET method")
    )
    respx.post(mocking_link).mock(
        # Method GET that serve as a reference
        return_value=httpx.Response(200, text="Body from GET method")
    )
    respx.delete(mocking_link).mock(
        # Method returning the method not allowed server code so it won't be listed
        return_value=httpx.Response(405, text="Not supposed to reach that")
    )
    respx.put(mocking_link).mock(
        # Method with the same server return code but a different body
        return_value=httpx.Response(
            200, text="Same return code but different body")
    )
    respx.patch(mocking_link).mock(
        # Method with a different server return code but the same body
        return_value=httpx.Response(500, text="Body from GET method")
    )

    persister = AsyncMock()
    request = Request(mocking_link)
    request.path_id = 1
    response = Response(
        httpx.Response(status_code=200),
        url=mocking_link
    )
    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleMethods(crawler, persister, options, Event(), crawler_configuration)
        module.do_get = True
        await module.attack(request, response)

        assert persister.add_payload.call_count == 1
        assert (
            "Possible interesting methods (using OPTIONS) on http://perdu.com/dummy/: "
            "OPTIONS (200) PATCH (500) PUT (200)"
        ) == persister.add_payload.call_args_list[0][1]["info"]


@pytest.mark.asyncio
@respx.mock
async def test_blind_with_trace():
    mocking_link = "http://perdu.com/dummy/"

    # Content bellow are the same as GET so should be ignored
    for method in ("GET", "POST", "PUT", "OPTIONS", "HEAD", "DELETE"):
        respx.request(method, mocking_link).mock(
            return_value=httpx.Response(
                200,
                text="Welcome",
            )
        )

    # Trace is activated and return the request
    respx.request("TRACE", mocking_link).mock(
        # Method with a different server return code but the same body
        return_value=httpx.Response(200, text="TRACE /")
    )

    # Patch gives something unusual
    respx.patch(mocking_link).mock(
        return_value=httpx.Response(200, text="This is something secret"),
    )

    # Common behavior for CONNECT should be ignored
    respx.request("CONNECT", mocking_link).mock(
        return_value=httpx.Response(400, text="Invalid request"),
    )

    persister = AsyncMock()
    request = Request(mocking_link)
    request.path_id = 1
    response = Response(
        httpx.Response(status_code=200),
        url=mocking_link
    )
    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleMethods(crawler, persister, options, Event(), crawler_configuration)
        module.do_get = True
        await module.attack(request, response)

        assert persister.add_payload.call_count == 2
        assert "HTTP TRACE method is allowed on the webserver" == persister.add_payload.call_args_list[0][1]["info"]
        assert (
                "Possible interesting methods (using heuristics) on http://perdu.com/dummy/: PATCH (200) TRACE (200)"
               ) == persister.add_payload.call_args_list[1][1]["info"]

        # All HTTP verbs should have been used
        assert len({call.request.method for call in respx.calls}) == 9
