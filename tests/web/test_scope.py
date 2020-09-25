import responses
import requests

from wapitiCore.net.crawler import Page, Crawler, Scope
from wapitiCore.net.web import Request


@responses.activate
def test_domain_scope():
    url = "http://perdu.com/"
    responses.add(
        responses.GET,
        url,
        body="Hello world!"
    )

    resp = requests.get(url)
    page = Page(resp)
    assert page.is_external_to_domain("http://yolo.tld")
    assert page.is_external_to_domain("http://www.google.com/")
    assert page.is_external_to_domain("http://jesuisperdu.com/")
    assert not page.is_external_to_domain("http://perdu.com/robots.txt")
    assert not page.is_external_to_domain("http://www.perdu.com/blog/")
    assert not page.is_external_to_domain("https://perdu.com/blog/")
    assert not page.is_external_to_domain("http://perdu.com:80/blog/")
    assert page.is_external_to_domain("http://perdu.com.org/blog/")


def test_scopes():
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

    crawler = Crawler("http://perdu.com/subdir/")
    crawler.scope = Scope.FOLDER
    filtered = {link for link in links if crawler.is_in_scope(Request(link))}
    assert filtered == {
        "http://perdu.com/subdir/subdirpage.html",
        "http://perdu.com/subdir/subdir2/subdirpage2.html",
        "http://perdu.com/subdir/page.html?k=v",
        "http://perdu.com/subdir/page.html",
    }

    crawler = Crawler("http://perdu.com/subdir/page.html")
    crawler.scope = Scope.PAGE
    filtered = {link for link in links if crawler.is_in_scope(Request(link))}
    assert filtered == {
        "http://perdu.com/subdir/page.html?k=v",
        "http://perdu.com/subdir/page.html"
    }

    crawler = Crawler("http://perdu.com/subdir/page.html?k=v")
    crawler.scope = Scope.URL
    filtered = {link for link in links if crawler.is_in_scope(Request(link))}
    assert filtered == {
        "http://perdu.com/subdir/page.html?k=v"
    }

    crawler = Crawler("http://perdu.com/subdir/page.html?k=v")
    crawler.scope = Scope.DOMAIN
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

    crawler = Crawler("http://perdu.com/subdir/page.html?k=v")
    crawler.scope = Scope.PUNK
    filtered = {link for link in links if crawler.is_in_scope(Request(link))}
    assert filtered == links
