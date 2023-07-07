from asyncio import Event
from unittest.mock import AsyncMock

import httpx
import pytest
import respx

from tests import AsyncIterator
from wapitiCore.attack.attack import Parameter, ParameterSituation, PayloadType
from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_permanentxss import ModulePermanentxss
from wapitiCore.net.xss_utils import PayloadInfo

values = ["iamgroot"]


def return_stored_values(_):
    global values
    return httpx.Response(200, text="\n".join(values), headers={"Content-Type": "text/html"})


def add_value(request):
    global values
    values.append(request.url.params.get("message"))
    return httpx.Response(200, text="Comment saved")


def store_and_return_stored_value(request):
    global values
    values.append(request.url.params.get("message"))
    return httpx.Response(
        200,
        text="\n".join(values + ['<div id="iamgroot">success</div>']),
        headers={"Content-Type": "text/html"}
    )


@pytest.mark.asyncio
@respx.mock
async def test_second_order_injection():
    respx.get("http://perdu.com/").mock(side_effect=return_stored_values)
    respx.get(url__regex=r"http://perdu\.com/comment\.php\?message=.*").mock(side_effect=add_value)

    # We should succeed at escaping the title tag
    persister = AsyncMock()
    index_request = Request("http://perdu.com/")
    index_request.path_id = 1

    comment_request = Request("http://perdu.com/comment.php?message=Hello")
    comment_request.path_id = 2

    persister.get_links.return_value = AsyncIterator([(index_request, None), (comment_request, None)])

    crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:65081/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModulePermanentxss(crawler, persister, options, Event(), crawler_configuration)
        module.do_post = False
        module.tried_xss["iamgroot"] = (
            comment_request,
            Parameter(name="message", situation=ParameterSituation.QUERY_STRING)
        )

        await module.attack(index_request)

        assert persister.add_payload.call_count
        assert persister.add_payload.call_args_list[0][1]["module"] == "permanentxss"
        assert persister.add_payload.call_args_list[0][1]["category"] == "Stored Cross Site Scripting"
        assert persister.add_payload.call_args_list[0][1]["parameter"] == "message"
        assert persister.add_payload.call_args_list[0][1]["request"].get_params[0][1] == (
            "<ScRiPt>alert('iamgroot')</sCrIpT>"
        )


@pytest.mark.asyncio
@respx.mock
async def test_first_order_injection():
    # Injection and rendering occurs in the same webpage
    respx.get(url__regex=r"http://perdu\.com/comment\.php\?message=.*").mock(side_effect=store_and_return_stored_value)

    # We should succeed at escaping the title tag
    persister = AsyncMock()
    comment_request = Request("http://perdu.com/comment.php?message=Hello")
    comment_request.path_id = 1

    evil_request = Request("http://perdu.com/comment.php?message=%3Cdiv%20id%3D%22imgroot%22%3Eyolo%3C/div%3E")
    evil_request.path_id = 2

    persister.get_links.return_value = AsyncIterator([(comment_request, None)])

    crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:65081/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModulePermanentxss(crawler, persister, options, Event(), crawler_configuration)
        module.do_post = False
        module.tried_xss["iamgroot"] = (
            comment_request,
            Parameter(name="message", situation=ParameterSituation.QUERY_STRING)
        )
        module.successful_xss["iamgroot"] = (
            evil_request,
            PayloadInfo(
                payload='<div id="iamgroot">success</div>',
                injection_type="html",
                name="html_inject",
                type=PayloadType.xss_closing_tag,
            )
        )

        await module.attack(comment_request)

        assert persister.add_payload.call_count
        assert persister.add_payload.call_args_list[0][1]["module"] == "permanentxss"
        assert persister.add_payload.call_args_list[0][1]["category"] == "Stored HTML Injection"
        assert persister.add_payload.call_args_list[0][1]["parameter"] == "message"
        assert persister.add_payload.call_args_list[0][1]["request"].get_params[0][1] == (
            '<div id="imgroot">yolo</div>'
        )
