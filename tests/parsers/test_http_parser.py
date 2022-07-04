import respx
import httpx

from wapitiCore.net.crawler import Response


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

    response = Response(httpx.get(url))

    assert response.status == 418
    assert response.headers["X-Men"] == "Wolverine"
    assert response.url == "http://perdu.com/"
    assert response.server == "nginx"
    assert response.cookies["session_id"] == "31337"
    assert response.is_plain
    assert response.size == response.raw_size != 0
    assert response.delay > 0
    assert isinstance(response.bytes, bytes) and response.bytes
    assert response.type == "text/html; charset=iso-8859-1"
    assert response.encoding == "ISO-8859-1"  # see https://github.com/encode/httpx/pull/1269


@respx.mock
def test_http_redir():
    url = "http://perdu.com/folder"
    respx.get(url).mock(
        return_value=httpx.Response(301, text="Hello world!", headers={"Location": "http://perdu.com/folder/"})
    )

    resp = httpx.get(url, follow_redirects=False)
    page = Response(resp)
    assert page.is_directory_redirection
