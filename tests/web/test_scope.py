import pytest

import httpx
import respx

from wapitiCore.net.crawler import Response
from wapitiCore.parsers.html_parser import Html
from wapitiCore.net import Request
from wapitiCore.net.scope import Scope, wildcard_translate


@respx.mock
def test_domain_scope():
    url = "http://perdu.com/"
    respx.get(url).mock(return_value=httpx.Response(200, text="Hello world!"))

    resp = httpx.get(url)
    page = Html(Response(resp).content, url)
    assert page.is_external_to_domain("http://yolo.tld")
    assert page.is_external_to_domain("http://www.google.com/")
    assert page.is_external_to_domain("http://jesuisperdu.com/")
    assert not page.is_external_to_domain("http://perdu.com/robots.txt")
    assert not page.is_external_to_domain("http://www.perdu.com/blog/")
    assert not page.is_external_to_domain("https://perdu.com/blog/")
    assert not page.is_external_to_domain("http://perdu.com:80/blog/")
    assert page.is_external_to_domain("http://perdu.com.org/blog/")


@pytest.mark.asyncio
async def test_scopes():
    links = {
        "http://perdu.com/",
        "http://perdu.com/page.html",
        "http://perdu.com/subdir/subdirpage.html",
        "http://perdu.com/subdir/subdir2/subdirpage2.html",
        "http://sub.perdu.com/page.html",
        "https://perdu.com/secure.html",
        "http://perdu.com/subdir/page.html?k=v",
        "http://perdu.com/subdir/page.html",
        "http://lost.com/lost.html",
        "http://external.tld/external.html",
        "https://subdomain.perdu.com/",
        "http://subdomain.perdu.com/",
        "http://subdomain.perdu.com/page.html",
        "http://subdomain.perdu.com/subdir/subdirpage.html",
    }

    scope = Scope(Request("http://perdu.com/subdir/"), "folder")
    assert scope.filter(links) == {
        "http://perdu.com/subdir/subdirpage.html",
        "http://perdu.com/subdir/subdir2/subdirpage2.html",
        "http://perdu.com/subdir/page.html?k=v",
        "http://perdu.com/subdir/page.html",
    }

    scope = Scope(Request("http://perdu.com/subdir/page.html"), "page")
    assert scope.filter(links) == {
        "http://perdu.com/subdir/page.html?k=v",
        "http://perdu.com/subdir/page.html"
    }

    scope = Scope(Request("http://perdu.com/subdir/page.html?k=v"), "url")
    assert scope.filter(links) == {
        "http://perdu.com/subdir/page.html?k=v"
    }

    scope = Scope(Request("http://perdu.com/subdir/page.html?k=v"), "domain")
    assert scope.filter(links) == {
        "http://perdu.com/",
        "http://perdu.com/page.html",
        "http://perdu.com/subdir/subdirpage.html",
        "http://perdu.com/subdir/subdir2/subdirpage2.html",
        "http://sub.perdu.com/page.html",
        "https://perdu.com/secure.html",
        "http://perdu.com/subdir/page.html?k=v",
        "http://perdu.com/subdir/page.html",
        "http://subdomain.perdu.com/",
        "http://subdomain.perdu.com/page.html",
        "http://subdomain.perdu.com/subdir/subdirpage.html",
        "https://subdomain.perdu.com/"
    }

    scope = Scope(Request("http://subdomain.perdu.com/subdir/page.html?k=v"), "subdomain")
    assert scope.filter(links) == {
        "http://subdomain.perdu.com/",
        "http://subdomain.perdu.com/page.html",
        "http://subdomain.perdu.com/subdir/subdirpage.html",
        "https://subdomain.perdu.com/"
    }

    scope = Scope(Request("http://perdu.com/subdir/page.html?k=v"), "punk")
    assert scope.filter(links) == links


@pytest.mark.parametrize(
    "wildcard_expression, texts, results",
    [
        [
            "*way",
            ["thisistheway", "wayback machine", "away from here"],
            [True, False, False],
        ],
        [
            "this*",
            ["this is the way", "don't do this", "middle of this text"],
            [True, False, False],
        ],
        [
            "*days*",
            ["five days of tequilla", "back in the days", "days of the week"],
            [True, True, True],
        ],
        [
            "*machine*learning*",
            ["rage against the machine", "the machine is learning", "learning to use the machine"],
            [False, True, False],
        ]
    ],
    ids=[
        "ends with",
        "starts with",
        "middle of",
        "two words",
    ]
)
def test_wildcard_translate(wildcard_expression, texts, results):
    regex = wildcard_translate(wildcard_expression)
    for text, result in zip(texts, results):
        assert bool(regex.match(text)) is result
