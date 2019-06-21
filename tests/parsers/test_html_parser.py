import responses
import requests

from wapitiCore.net.crawler import Page


@responses.activate
def test_absolute_root():
    with open("tests/data/absolute_root_links.html") as fd:
        url = "http://perdu.com/"
        responses.add(
            responses.GET,
            url,
            body=fd.read()
        )

        resp = requests.get(url)
        page = Page(resp, url)

        assert page.links == [url]


@responses.activate
def test_relative_root():
    with open("tests/data/relative_root_links.html") as fd:
        url = "http://perdu.com/"
        responses.add(
            responses.GET,
            url,
            body=fd.read()
        )

        resp = requests.get(url)
        page = Page(resp, url)

        # We will get invalid hostnames with dots. Browsers do that too.
        assert set(page.links) == {url, "http://./", "http://../"}


@responses.activate
def test_relative_links():
    with open("tests/data/relative_links.html") as fd:
        url = "http://perdu.com/"
        responses.add(
            responses.GET,
            url,
            body=fd.read()
        )

        resp = requests.get(url)
        page = Page(resp, url)

        # We will get invalid hostnames with dots. Browsers do that too.
        assert set(page.links) == {
            url,
            "http://perdu.com/file.html",
            "http://perdu.com/resource",
            "http://perdu.com/folder/",
            "http://perdu.com/folder/file.html",
            "http://perdu.com/folder/file2.html",
            "http://perdu.com/file3.html",
            "http://perdu.com/?k=v",
            "http://perdu.com/file3.html?k=v",
            "http://perdu.com/folder/?k=v",
            "http://perdu.com/folder?k=v",
            "http://external.tld/",
            "http://external.tld/yolo?k=v",
        }
