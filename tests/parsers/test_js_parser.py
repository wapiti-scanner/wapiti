import responses
import requests

from wapitiCore.net.crawler import Page


@responses.activate
def test_absolute_root():
    with open("tests/data/js_links.html") as fd:
        url = "http://perdu.com/"
        responses.add(
            responses.GET,
            url,
            body=fd.read()
        )

        resp = requests.get(url)
        page = Page(resp, url)

        assert set(page.extra_urls) == {
            "http://perdu.com/onload.html",
            "http://perdu.com/popup.html",
            "http://perdu.com/redir.html",
            "http://perdu.com/concat.html",
            "http://perdu.com/concat.html?var=value",
            "http://perdu.com/link.html",
        }
