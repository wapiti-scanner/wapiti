import responses
import requests

from wapitiCore.net.crawler import Page


@responses.activate
def test_http():
    url = "http://perdu.com/"
    responses.add(
        responses.GET,
        url,
        body="Hello world!",
        adding_headers={
            "X-Men": "Wolverine",
            "Server": "nginx",
            "Set-Cookie": "session_id=31337;",
            "Content-Type": "text/html"
        },
        status=418
    )

    resp = requests.get(url)
    page = Page(resp)

    assert page.status == 418
    assert page.headers["X-Men"] == "Wolverine"
    assert page.url == "http://perdu.com/"
    assert page.server == "nginx"
    assert page.cookies["session_id"] == "31337"
    assert page.is_plain
    assert page.size == page.raw_size != 0
    assert page.delay > 0
    assert isinstance(page.bytes, bytes) and len(page.bytes)
    assert page.type == "text/html"
    assert page.encoding == "ISO-8859-1"


@responses.activate
def test_http():
    url = "http://perdu.com/folder"
    responses.add(
        responses.GET,
        url,
        body="Hello world!",
        adding_headers={
            "Location": "http://perdu.com/folder/",
        },
        status=301
    )

    resp = requests.get(url, allow_redirects=False)
    page = Page(resp)
    assert page.is_directory_redirection
