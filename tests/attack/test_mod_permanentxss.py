from asyncio import Event
from unittest.mock import AsyncMock

import httpx
import pytest
import respx

from tests import AsyncIterator
from wapitiCore.attack.attack import Parameter, ParameterSituation
from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_permanentxss import ModulePermanentxss

values = ["iamgroot"]


def return_stored_values(_):
    global values
    return httpx.Response(200, text="\n".join(values), headers={"Content-Type": "text/html"})


def add_value(request):
    global values
    values.append(request.url.params.get("message"))
    return httpx.Response(200, text="Comment saved")


@pytest.mark.asyncio
@respx.mock
async def test_vulnerable_page():
    respx.get("http://perdu.com/").mock(side_effect=return_stored_values)
    respx.get(url__regex=r"http://perdu\.com/comment\.php\?message=.*").mock(side_effect=add_value)

    # We should succeed at escaping the title tag
    persister = AsyncMock()
    index_request = Request("http://perdu.com/")
    index_request.path_id = 1

    comment_request = Request("http://perdu.com/comment.php?message=Hello")
    comment_request.path_id = 2

    persister.get_links.return_value = AsyncIterator([(index_request, comment_request)])

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
