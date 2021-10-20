import respx
import httpx

from wapitiCore.net.crawler import Page


@respx.mock
def test_http():
    url = "http://perdu.com/"
    respx.get(url).mock(
        return_value=httpx.Response(
            418,
            headers={
                "X-Men": "Wolverine",
                "Server": "nginx",
                "Set-Cookie": "session_id=31337;",
                "Content-Type": "text/html; charset=ISO-8859-1"
            },
            text="Hello world!"
        )
    )

    resp = httpx.get(url)
    page = Page(resp)

    assert page.status == 418
    assert page.headers["X-Men"] == "Wolverine"
    assert page.url == "http://perdu.com/"
    assert page.server == "nginx"
    assert page.cookies["session_id"] == "31337"
    assert page.is_plain
    assert page.size == page.raw_size != 0
    assert page.delay > 0
    assert isinstance(page.bytes, bytes) and page.bytes
    assert page.type == "text/html; charset=iso-8859-1"
    assert page.encoding == "ISO-8859-1"  # see https://github.com/encode/httpx/pull/1269


@respx.mock
def test_http_redir():
    url = "http://perdu.com/folder"
    respx.get(url).mock(
        return_value=httpx.Response(301, text="Hello world!", headers={"Location": "http://perdu.com/folder/"})
    )

    resp = httpx.get(url, follow_redirects=False)
    page = Page(resp)
    assert page.is_directory_redirection
