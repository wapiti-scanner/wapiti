from asyncio import Event
from unittest.mock import AsyncMock

import httpx
import respx
import pytest
from unittest.mock import patch
import dns
import dns.message
import dns.resolver

from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_takeover import ModuleTakeover, TakeoverChecker


CNAME_TEMPLATE = """id 5395
opcode QUERY
rcode NOERROR
flags QR RD RA
;QUESTION
{qname}. IN CNAME
;ANSWER
{qname}. 3035 IN CNAME {cname}.
;AUTHORITY
;ADDITIONAL"""


def make_cname_answer(qname, cname):
    message = dns.message.from_text(CNAME_TEMPLATE.format(qname=qname, cname=cname))
    qname = dns.name.from_text(qname)
    answer = dns.resolver.Answer(qname, dns.rdatatype.A, dns.rdataclass.IN, message)
    return answer


@pytest.mark.asyncio
@respx.mock
async def test_unregistered_cname():
    # Test attacking all kind of parameter without crashing
    respx.route(host="perdu.com").mock(return_value=httpx.Response(200, text="Hello there"))

    async def resolve(qname, rdtype, raise_on_no_answer: bool = False):
        if qname.startswith("supercalifragilisticexpialidocious."):
            # No wildcard responses
            return []
        if qname.startswith("admin.") and rdtype == "CNAME":
            return make_cname_answer("perdu.com", "unregistered.com")
        raise dns.resolver.NXDOMAIN("Yolo")

    with patch("wapitiCore.attack.mod_takeover.dns.asyncresolver.resolve") as mocked_resolve_:
        with patch("wapitiCore.attack.mod_takeover.dns.asyncresolver.Resolver.resolve") as mocked_resolve:
            mocked_resolve.side_effect = resolve
            mocked_resolve_.side_effect = resolve
            persister = AsyncMock()
            all_requests = []

            request = Request("http://perdu.com/")
            request.path_id = 1
            all_requests.append(request)

            crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
            async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
                options = {"timeout": 10, "level": 2}

                module = ModuleTakeover(crawler, persister, options, Event(), crawler_configuration)

                for request in all_requests:
                    await module.attack(request)

                assert persister.add_payload.call_args_list[0][1]["request"].hostname == "admin.perdu.com"
                assert "unregistered.com" in persister.add_payload.call_args_list[0][1]["info"]


@pytest.mark.asyncio
@respx.mock
async def test_github_io_false_positive():
    respx.get("https://victim.com/").mock(
        return_value=httpx.Response(200, text="There isn't a GitHub Pages site here")
    )

    respx.head("https://github.com/falsepositive").mock(
        return_value=httpx.Response(200, text="I'm registered")
    )

    takeover = TakeoverChecker()
    assert not await takeover.check("victim.com", "falsepositive.github.io")


@pytest.mark.asyncio
@respx.mock
async def test_github_io_true_positive():
    respx.get("https://victim.com/").mock(
        return_value=httpx.Response(200, text="There isn't a GitHub Pages site here")
    )

    respx.head("https://github.com/truepositive").mock(
        return_value=httpx.Response(404, text="No such user")
    )

    takeover = TakeoverChecker()
    assert await takeover.check("victim.com", "truepositive.github.io")


@pytest.mark.asyncio
@respx.mock
async def test_myshopify_false_positive():
    respx.get("https://victim.com/").mock(
        return_value=httpx.Response(200, text="Sorry, this shop is currently unavailable")
    )

    myshopify_api_url = (
        "https://app.shopify.com/services/signup/check_availability.json?"
        f"shop_name=falsepositive&email=test@example.com"
    )
    respx.get(myshopify_api_url).mock(
        return_value=httpx.Response(200, json={"status": "unavailable"})
    )

    takeover = TakeoverChecker()
    assert not await takeover.check("victim.com", "falsepositive.myshopify.com")


@pytest.mark.asyncio
@respx.mock
async def test_myshopify_true_positive():
    respx.get("https://victim.com/").mock(
        return_value=httpx.Response(200, text="Sorry, this shop is currently unavailable")
    )

    myshopify_api_url = (
        "https://app.shopify.com/services/signup/check_availability.json?"
        f"shop_name=falsepositive&email=test@example.com"
    )
    respx.get(myshopify_api_url).mock(
        return_value=httpx.Response(200, json={"status": "available"})
    )

    takeover = TakeoverChecker()
    assert await takeover.check("victim.com", "falsepositive.myshopify.com")
