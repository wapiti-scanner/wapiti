import pytest

import httpx
import respx

from wapitiCore.net.crawler import Response, AsyncCrawler, Scope
from wapitiCore.net.crawler_configuration import CrawlerConfiguration
from wapitiCore.net.web import Request


@respx.mock
def test_domain_scope():
    url = "http://perdu.com/"
    respx.get(url).mock(return_value=httpx.Response(200, text="Hello world!"))

    resp = httpx.get(url)
    page = Response(resp)
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

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/subdir/"), scope=Scope.FOLDER)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        filtered = {link for link in links if crawler.is_in_scope(Request(link))}
        assert filtered == {
            "http://perdu.com/subdir/subdirpage.html",
            "http://perdu.com/subdir/subdir2/subdirpage2.html",
            "http://perdu.com/subdir/page.html?k=v",
            "http://perdu.com/subdir/page.html",
        }

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/subdir/page.html"), scope=Scope.PAGE)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        filtered = {link for link in links if crawler.is_in_scope(Request(link))}
        assert filtered == {
            "http://perdu.com/subdir/page.html?k=v",
            "http://perdu.com/subdir/page.html"
        }

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/subdir/page.html?k=v"), scope=Scope.URL)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        filtered = {link for link in links if crawler.is_in_scope(Request(link))}
        assert filtered == {
            "http://perdu.com/subdir/page.html?k=v"
        }

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/subdir/page.html?k=v"), scope=Scope.DOMAIN)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        filtered = {link for link in links if crawler.is_in_scope(Request(link))}
        assert filtered == {
            "http://perdu.com/",
            "http://perdu.com/page.html",
            "http://perdu.com/subdir/subdirpage.html",
            "http://perdu.com/subdir/subdir2/subdirpage2.html",
            "http://sub.perdu.com/page.html",
            "https://perdu.com/secure.html",
            "http://perdu.com/subdir/page.html?k=v",
            "http://perdu.com/subdir/page.html"
        }

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/subdir/page.html?k=v"), scope=Scope.PUNK)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        filtered = {link for link in links if crawler.is_in_scope(Request(link))}
        assert filtered == links
