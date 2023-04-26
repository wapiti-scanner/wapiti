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

    # Link to test the module if there is nothing to discover
    respx.options(mocking_links[0]).mock(
        return_value=httpx.Response(200, text="Default page", headers={"Allow": "GET,POST,HEAD"})
    )
    respx.get(mocking_links[0]).mock(
        return_value=httpx.Response(200, text="Body from GET option")
    )

    # Link to test the module in the following cases:
    # - Different server code and different body
    # - Same server code and same body
    respx.options(mocking_links[1]).mock(
        # Method OPTIONS that discover the other methods
        return_value=httpx.Response(200, text="Private section", headers={"Allow": "GET,POST,HEAD,PUT,DELETE"})
    )
    respx.get(mocking_links[1]).mock(
        return_value=httpx.Response(200, text="Body from GET option")
    )
    respx.put(mocking_links[1]).mock(
        return_value=httpx.Response(500, text="Body from PUT method")
    )
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

    crawler_configuration = CrawlerConfiguration(
        Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleMethods(crawler, persister, options,
                               Event(), crawler_configuration)
        module.do_get = True
        for request, response in all_requests:
            await module.attack(request, response)

        assert persister.add_payload.call_count == 2
        # Below, tuple containing string (link) followed by
        # dicts of sets which are their wanted/unwanted method associated
        check_strings = (mocking_links[1], {'wanted': {'PUT'},
                                            'unwanted': {'GET', 'POST', 'DELETE', 'HEAD'},
                                            })
        assert check_strings[0] in persister.add_payload.call_args_list[0][1]["info"]
        # Check if every wanted methods is detected
        assert any(s in persister.add_payload.call_args_list[0][1]["info"] for s in check_strings[1]['wanted'])
        # Check for any unwanted and detected methods
        assert not all(s in persister.add_payload.call_args_list[0][1]["info"] for s in check_strings[1]['unwanted'])


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
        return_value=httpx.Response(200, text="Body from OPTIONS method", headers={
                                    "Allow": "GET,POST,HEAD,PUT,DELETE,PATCH"})
    )
    respx.get(mocking_link).mock(
        # Method GET that serve as a reference
        return_value=httpx.Response(200, text="Body from GET method")
    )
    respx.delete(mocking_link).mock(
        # Method returning the method not allowed server code so it won't be listed
        return_value=httpx.Response(405, text="Not supposed to reach that")
    )
    respx.put(mocking_link).mock(
        # Method with the same server retrun code but a different body
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
    crawler_configuration = CrawlerConfiguration(
        Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleMethods(crawler, persister, options,
                               Event(), crawler_configuration)
        module.do_get = True
        await module.attack(request, response)

        assert persister.add_payload.call_count == 3
        # Below, tuple containing string (link) followed by
        # dicts of sets which are their wanted/unwanted method associated
        check_strings = (mocking_link, {'wanted': {'PUT', 'PATCH'},
                                        'unwanted': {'DELETE'}
                                        })
        assert check_strings[0] in persister.add_payload.call_args_list[0][1]["info"]
        for i in range(len(check_strings[1])):
            # Check if every wanted methods is detected
            assert any(s in persister.add_payload.call_args_list[i][1]["info"] for s in check_strings[1]['wanted'])
            # Check for any unwanted and detected methods
            assert not all(s in persister.add_payload.call_args_list[i][1]["info"]
                           for s in check_strings[1]['unwanted'])


@pytest.mark.asyncio
@respx.mock
async def test_blind_options():
    # Mock a website with an empty option method
    mocking_link = "http://perdu.com/dummy/"

    # first, we mock an empty option method
    respx.options(mocking_link).mock(
        return_value=httpx.Response(200, text="Body from OPTIONS method")
    )

    supported_methods = ["GET", "POST", "HEAD", "TRACE", "CONNECT", "DELETE", "PUT", "PATCH"]
    half_size_supported_methods = int(len(supported_methods)/2)
    # We define half of the method as good, the other ones as not allowed
    mock_responses = {}
    for i, method in enumerate(supported_methods):
        if i < half_size_supported_methods:
            mock_responses.update({method: httpx.Response(200, text=f"Body from {method} method")})
        else:
            mock_responses.update({method: httpx.Response(405, text=f"Body from {method} method")})

    for method, response in mock_responses.items():
        respx.route(method=method, url=mocking_link).mock(
            return_value=response
        )

    persister = AsyncMock()
    request = Request(mocking_link)
    request.path_id = 1
    response = Response(
        httpx.Response(status_code=200),
        url=mocking_link
    )
    crawler_configuration = CrawlerConfiguration(
        Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleMethods(crawler, persister, options,
                               Event(), crawler_configuration)
        module.do_get = True
        await module.attack(request, response)

        assert persister.add_payload.call_count == 5
        # Below, tuple containing string (link) followed by
        # dicts of sets which are their wanted/unwanted method associated
        check_strings = (mocking_link, {'wanted': set(supported_methods[:half_size_supported_methods]),
                                        'unwanted': set(supported_methods[half_size_supported_methods:])
                                        })
        assert check_strings[0] in persister.add_payload.call_args_list[0][1]["info"]
        for i, method in enumerate(supported_methods[:half_size_supported_methods]):
            # Check if every wanted methods is detected
            assert any(s in persister.add_payload.call_args_list[i][1]["info"] for s in check_strings[1]['wanted'])
            # Check for any unwanted and detected methods
            assert not all(s in persister.add_payload.call_args_list[i][1]["info"]
                           for s in check_strings[1]['unwanted'])


@pytest.mark.asyncio
@respx.mock
async def test_not_allowed_options():
    # This test is the same as the blind options
    # When OPTIONS is not allowed, the module test each
    # method separately
    # Mock a website with an empty option method
    mocking_link = "http://perdu.com/dummy/"

    # first, we mock an empty option method
    respx.options(mocking_link).mock(
        return_value=httpx.Response(405, text="Body from OPTIONS method")
    )
    supported_methods = ["GET", "POST", "HEAD", "TRACE", "CONNECT", "DELETE", "PUT", "PATCH"]
    half_size_supported_methods = int(len(supported_methods)/2)
    # We define half of the method as good, the other ones as not allowed
    mock_responses = {}
    for i, method in enumerate(supported_methods):
        if i < half_size_supported_methods:
            mock_responses.update({method: httpx.Response(200, text=f"Body from {method} method")})
        else:
            mock_responses.update({method: httpx.Response(405, text=f"Body from {method} method")})

    for method, response in mock_responses.items():
        respx.route(method=method, url=mocking_link).mock(
            return_value=response
        )

    persister = AsyncMock()
    request = Request(mocking_link)
    request.path_id = 1
    response = Response(
        httpx.Response(status_code=200),
        url=mocking_link
    )
    crawler_configuration = CrawlerConfiguration(
        Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleMethods(crawler, persister, options,
                               Event(), crawler_configuration)
        module.do_get = True
        await module.attack(request, response)

        assert persister.add_payload.call_count == 4
        # Below, tuple containing string (link) followed by
        # dicts of sets which are their wanted/unwanted method associated
        check_strings = (mocking_link, {'wanted': set(supported_methods[:half_size_supported_methods]),
                                        'unwanted': set(supported_methods[half_size_supported_methods:])
                                        })
        assert check_strings[0] in persister.add_payload.call_args_list[0][1]["info"]
        for i, method in enumerate(supported_methods[:half_size_supported_methods]):
            # Check if every wanted methods is detected
            assert any(s in persister.add_payload.call_args_list[i][1]["info"] for s in check_strings[1]['wanted'])
            # Check for any unwanted and detected methods
            assert not all(s in persister.add_payload.call_args_list[i][1]["info"]
                           for s in check_strings[1]['unwanted'])
