import responses
import requests

from wapitiCore.net.crawler import Page


@responses.activate
def test_domain_scope():
    url = "http://perdu.com/"
    responses.add(
        responses.GET,
        url,
        body="Hello world!"
    )

    resp = requests.get(url)
    page = Page(resp, url)
    assert page.is_external_to_domain("http://yolo.tld")
    assert not page.is_external_to_domain("http://perdu.com/robots.txt")
    assert not page.is_external_to_domain("http://www.perdu.com/blog/")
    assert not page.is_external_to_domain("https://perdu.com/blog/")
    assert not page.is_external_to_domain("http://perdu.com:80/blog/")
    assert page.is_external_to_domain("http://perdu.com.org/blog/")
