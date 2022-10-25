import pytest

import httpx
import respx

from wapitiCore.net.crawler import Response
from wapitiCore.parsers.html_parser import Html
from wapitiCore.net import Request
from wapitiCore.net.scope import Scope


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
        "http://external.tld/external.html"
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
        "http://perdu.com/subdir/page.html"
    }

    scope = Scope(Request("http://perdu.com/subdir/page.html?k=v"), "punk")
    assert scope.filter(links) == links
