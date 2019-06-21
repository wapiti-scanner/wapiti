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
