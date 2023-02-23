#!/usr/bin/env python3
from hashlib import md5
from unittest import mock

import httpx
import respx
from bs4 import BeautifulSoup
from wapitiCore.net.response import Response
from wapitiCore.parsers.html_parser import Html
from wapitiCore.net.web import make_absolute


def test_make_absolute():
    test_cases = [
        ("http://base.url", "relative", "http://base.url/relative"),
        ("http://base.url", ".", "http://base.url/"),
        ("http://base.url/with_folder", ".", "http://base.url/"),
        ("http://base.url/with_folder", "./with_dot", "http://base.url/with_dot"),
        ("http://base.url/with_folder", "..", "http://base.url/"),
        ("http://base.url/with_folder", "../folder", "http://base.url/folder"),
        ("http://base.url", "http://whole.url", "http://whole.url/"),
        ("http://base.url", "https://whole.url", "https://whole.url/"),
        ("http://base.url", "http://whole.url:987", "http://whole.url:987/"),
        ("http://base.url", "https://whole.url:987", "https://whole.url:987/"),
        ("http://base.url", "/", "http://base.url/"),
        ("http://base.url", "//", ""),
        ("http://base.url", "//only_this", "http://only_this/"),
        ("http://base.url", "./..//", "http://base.url/"),
        ("http://base.url", "./wrong_folder/../good_folder/", "http://base.url/good_folder/"),
        ("http://base.url", "http://perdu.com:80", "http://perdu.com/"),
        ("http://base.url", "https://secure.com:443", "https://secure.com/"),
        ("http://base.url", "https://mismatch.com:80", "https://mismatch.com:80/"),
        ("http://base.url", "http://mismatch.com:443", "http://mismatch.com:443/"),
    ]

    for base_url, relative_url, expected in test_cases:
        assert make_absolute(base_url, relative_url) == expected, \
            f"Absolute url from base_url='{base_url}' and relative_url='{relative_url}' is not '{expected}'"


@respx.mock
def test_page():
    target_url = "http://perdu.com/"
    page_headers = [
        ('server', 'nginx/1.19.0'),
        ('content-length', '229'),
        ('content-type', 'text/plain; charset=utf-8')
    ]
    page_links = [
        'http://perdu.com/action_page2.php',
        'https://foo.bar/',
        'https://abc.abc/',
        'http://perdu.com/action_page.php',
        'http://perdu.com/userinfo.php',
    ]
    page_extra_links = [
        'https://bar.foo/',
        'http://perdu.com/test.jpg',
        'http://perdu.com/javascript.js',
        'http://perdu.com/test.swf',
        'http://perdu.com/test.swf',
        'http://perdu.com/test.png',
    ]

    page_form_requests = [
        'http://perdu.com/action_page.php',
        'http://perdu.com/action_page2.php',
        'http://perdu.com/userinfo.php',
    ]

    page_content = """
    <html>
        <head>
            <title>Vous Etes Perdu ?</title>
            <meta name="color-scheme" content="dark light">
            <meta name="description" content="test">
            <meta name="keywords" content="lost">
            <meta name="generator" content="gen">
        </head>
        <body>
            <h1>Perdu sur l'Internet ?</h1>
            <h2>Pas de panique, on va vous aider</h2>
            <iframe id="foobarframe"
                title="Foobar Frame"
                width="300"
                height="200"
                src="https://foo.bar/">
            </iframe>
            <form name="loginform" method="post" action="userinfo.php">
                <table cellpadding="4" cellspacing="1">
                    <tr><td>Username : </td><td><input name="uname" type="text" size="20" style="width:120px;"></td></tr>
                    <tr><td>Password : </td><td><input name="pass" type="password" size="20" style="width:120px;"></td></tr>
                    <tr><td colspan="2" align="right"><input type="submit" value="login" style="width:75px;"></td></tr>
                </table>
            </form>
            <area shape="rect" coords="184,6,253,27"
                href="https://bar.foo"
                target="_blank" />
            <p>hello</p>
            <object type="application/x-shockwave-flash" data="/test.swf" width="800" height="360">
                <param name="movie" value="/test.swf">
                <param name="wmode" value="transparent">
                <p>You need to enable Flash to view this content.</p>
            </object>
            <a href="https://abc.abc/"></a>
            <form action="/action_page.php" method="get" class="form-example">
            </form>
            <img class="picture"
                src="/test.jpg"
                srcset="/test.png 2x">
                >
            <button class="foo bar"
                    type="button"
                    formaction="/action_page2.php"
                    >
                OK
            </button>
            <form action="/action_page2.php" method="get" class="form-example">
            </form>
            <script src="javascript.js"></script>
            <strong>
                <pre>    * <----- vous &ecirc;tes ici</pre>
            </strong>
        </body>
    </html>
    """

    respx.get(target_url).mock(
        return_value=httpx.Response(
            200,
            text=page_content,
            headers=page_headers,
        )
    )

    resp = httpx.get(target_url, follow_redirects=False)
    response = Response(resp)

    assert response.url == target_url
    assert response.history == []
    assert len(response.headers) == 3
    assert response.headers == page_headers
    assert len(response.cookies) == 0
    assert response.server == "nginx/1.19.0"
    assert response.is_plain is True
    assert response.size == 229
    assert response.raw_size == 229
    assert response.content == page_content
    assert response.bytes == str.encode(page_content)
    assert response.md5 == md5(str.encode(page_content)).hexdigest()
    assert response.status == 200
    assert response.type == "text/plain; charset=utf-8"
    assert response.redirection_url == ""
    assert response.is_directory_redirection is False

    html = Html(response.content, target_url)
    assert len(html.scripts) == 1
    assert html.scripts[0] == "http://perdu.com/javascript.js"
    assert next(html.iter_frames()) == "https://foo.bar/"

    assert len(html.links) == 5
    assert html.links.count(page_links[0]) == 1
    assert html.links.count(page_links[1]) == 1
    assert html.links.count(page_links[2]) == 1
    assert html.links.count(page_links[3]) == 1
    assert html.links.count(page_links[4]) == 1
    assert html.is_external_to_domain('http://perdu.com/blablabla/blablalba/blalba.html') is False
    assert html.is_external_to_domain('http://p3rdu.com/blablabla/blablalba/blalba.html') is True
    assert html.is_internal_to_domain('http://perdu.com/blablabla/blablalba/blalba.html') is True
    assert html.is_internal_to_domain('http://p3rdu.com/blablabla/blablalba/blalba.html') is False
    assert html.title == "Vous Etes Perdu ?"
    assert isinstance(html.soup, BeautifulSoup)
    assert html.base_url is None
    assert len(html.metas) == 4
    assert html.metas.get("color-scheme") == "dark light"
    assert html.description == "test"
    assert html.keywords == ["lost"]
    assert html.generator == "gen"
    assert html.text_only is not None # @fixme later
    assert html.text_only_md5 is not None # @fixme
    assert html.favicon_url == target_url + "favicon.ico"
    assert len(html.images_urls) == 1
    assert html.images_urls[0] == target_url + "test.jpg"
    for url in html.extra_urls:
        assert url in page_extra_links
    assert len(html.js_redirections) == 0
    assert len(html.html_redirections) == 0
    assert len(html.all_redirections) == 0
    for request in html.iter_forms():
        assert request.url in page_form_requests
    login_form, username_field, password_field = html.find_login_form()
    assert username_field == 0
    assert password_field == 1
    assert login_form.url == "http://perdu.com/userinfo.php"
    assert login_form.encoded_data == "uname=&pass="


@respx.mock
def test_size_page():
    target_url_1 = "http://perdu.com/"
    target_url_2 = "http://perdu2.com/"
    target_url_3 = "http://perdu3.com/"
    page_headers_1 = [
        ('content-length', '229,23'),
    ]

    page_headers_2 = [
        ('content-length', '240;23'),
    ]
    page_content = """
    <html>
        <head>
            <title>Test</title>
        </head>
        <body>
        </body>
    </html>
    """

    respx.get(target_url_1).mock(
        return_value=httpx.Response(
            200,
            text=page_content,
            headers=page_headers_1,
        )
    )

    resp = httpx.get(target_url_1, follow_redirects=False)
    page = Response(resp)

    assert page.size == 229

    respx.get(target_url_2).mock(
        return_value=httpx.Response(
            200,
            text=page_content,
            headers=page_headers_2,
        )
    )

    resp = httpx.get(target_url_2, follow_redirects=False)
    page = Response(resp)

    assert page.size == 240

    respx.get(target_url_3).mock(
        return_value=httpx.Response(
            200,
            text=page_content,
            headers=(),
        )
    )

    resp = httpx.get(target_url_3, follow_redirects=False)
    page = Response(resp)

    assert page.size == 122


@respx.mock
def test_raw_size_page():
    target_url_1 = "http://perdu.com/"
    target_url_2 = "http://perdu2.com/"
    target_url_3 = "http://perdu3.com/"
    page_headers_1 = [
        ('content-length', '229,23'),
    ]
    page_headers_2 = [
        ('content-length', '240;23'),
    ]
    page_content = """
    <html>
        <head>
            <title>Test</title>
        </head>
        <body>
        </body>
    </html>
    """

    respx.get(target_url_1).mock(
        return_value=httpx.Response(
            200,
            text=page_content,
            headers=page_headers_1,
        )
    )

    respx.get(target_url_2).mock(
        return_value=httpx.Response(
            200,
            text=page_content,
            headers=page_headers_2,
        )
    )

    respx.get(target_url_3).mock(
        return_value=httpx.Response(
            200,
            text=page_content,
            headers=(),
        )
    )

    resp = httpx.get(target_url_1, follow_redirects=False)
    page = Response(resp)

    assert page.raw_size == 229

    resp = httpx.get(target_url_2, follow_redirects=False)
    page = Response(resp)

    assert page.raw_size == 240

    resp = httpx.get(target_url_3, follow_redirects=False)
    page = Response(resp)

    assert page.size == 122


@respx.mock
def test_content_page():
    target_url_1 = "http://perdu.com/"
    target_url_2 = "http://perdu2.com/"
    target_url_3 = "http://perdu3.com/"
    page_content_1 = "foobar"
    page_content_2 = ""

    respx.get(target_url_1).mock(
        return_value=httpx.Response(
            200,
            text=page_content_1,
        )
    )

    respx.get(target_url_2).mock(
        return_value=httpx.Response(
            200,
            text=page_content_2,
        )
    )

    respx.get(target_url_3).mock(
        return_value=httpx.Response(
            200,
            text=page_content_1,
        )
    )

    resp = httpx.get(target_url_1, follow_redirects=False)
    page = Response(resp)

    assert page.content == "foobar"

    resp = httpx.get(target_url_2, follow_redirects=False)
    page = Response(resp)

    assert page.content == ""


@respx.mock
def test_bytes_page():
    target_url_1 = "http://perdu.com/"
    page_content_1 = ""

    respx.get(target_url_1).mock(
        return_value=httpx.Response(
            200,
            text=page_content_1,
        )
    )

    resp = httpx.get(target_url_1, follow_redirects=False)
    page = Response(resp)

    assert page.bytes == b""


@respx.mock
def test_json_page():
    target_url_1 = "http://perdu.com/"
    target_url_2 = "http://perdu2.com/"
    target_url_3 = "http://perdu3.com/"

    page_content_1 = None
    page_content_2 = "{'a': 1}"
    page_content_3 = None

    respx.get(target_url_1).mock(
        return_value=httpx.Response(
            200,
            text=page_content_1,
        )
    )
    respx.get(target_url_2).mock(
        return_value=httpx.Response(
            200,
            text=page_content_2,
        )
    )

    respx.get(target_url_3).mock(
        return_value=httpx.Response(
            200,
            text=page_content_3,
        )
    )

    resp = httpx.get(target_url_1, follow_redirects=False)
    page = Response(resp)

    assert page.json is None

    mock.patch('httpx.Response.json', return_value=ValueError(None))

    resp = httpx.get(target_url_2, follow_redirects=False)
    page = Response(resp)

    assert page.json == {'a': 1}

    resp = httpx.get(target_url_3, follow_redirects=False)
    page = Response(resp)
    mock.patch('httpx.Response.json', return_value=ValueError(None))
    mock.patch('ast.literal_eval', return_value=ValueError(None))
    assert page.json is None


@respx.mock
def test_scripts_page():
    target_url_1 = "http://perdu.com/"
    target_url_2 = "http://perdu2.com/"
    target_url_3 = "http://perdu3.com/"
    target_url_4 = "http://perdu4.com/"
    target_url_5 = "http://perdu5.com/"

    page_content_1 = "<script src='javascript.js'></script>"
    page_content_2 = "<script src='https:///?foo=bar'></script>"
    page_content_3 = "<script src='https://user:pass@NetLoc:80/awesome-script.js'></script>"
    page_content_4 = "<script src='user:pass@NetLoc:80/awesome-script.js'></script>"
    page_content_5 = "<script src='http://netloc/awesome-script.js'></script>"

    respx.get(target_url_1).mock(
        return_value=httpx.Response(
            200,
            text=page_content_1,
        )
    )
    respx.get(target_url_2).mock(
        return_value=httpx.Response(
            200,
            text=page_content_2,
        )
    )
    respx.get(target_url_3).mock(
        return_value=httpx.Response(
            200,
            text=page_content_3,
        )
    )
    respx.get(target_url_4).mock(
        return_value=httpx.Response(
            200,
            text=page_content_4,
        )
    )
    respx.get(target_url_5).mock(
        return_value=httpx.Response(
            200,
            text=page_content_5,
        )
    )
    # internal url
    resp = httpx.get(target_url_1, follow_redirects=False)
    page = Html(Response(resp).content, target_url_1)
    assert len(page.scripts) == 1
    assert page.scripts[0] == "http://perdu.com/javascript.js"

    # wrongly formatted url
    resp = httpx.get(target_url_2, follow_redirects=False)
    page = Html(Response(resp).content, target_url_2)
    assert len(page.scripts) == 0

    # with scheme & netloc
    resp = httpx.get(target_url_3, follow_redirects=False)
    page = Html(Response(resp).content, target_url_3)
    assert len(page.scripts) == 1
    assert page.scripts[0] == "https://user:pass@NetLoc:80/awesome-script.js"

    # without scheme but with netloc
    resp = httpx.get(target_url_4, follow_redirects=False)
    page = Html(Response(resp).content, target_url_4)
    assert len(page.scripts) == 0

    # without extension
    resp = httpx.get(target_url_5, follow_redirects=False)
    page = Html(Response(resp).content, target_url_5)
    assert len(page.scripts) == 1
    assert page.scripts[0] == "http://netloc/awesome-script.js"


@respx.mock
def test_soup_page():
    target_url_1 = "http://perdu.com/"

    page_content_1 = """
    <html>
        <head>
            <title>Foobar</title>
        </head>
        <body>
            <h1>Perdu sur l'Internet ?</h1>
        </body>
    </html>
    """
    target_url_2 = "http://perdu2.com/"

    page_content_2 = """
    <html>
        <head>
            <title>Foobar</title>
            <base href="https://example.com" />
        </head>
        <body>
            <h1>Perdu sur l'Internet ?</h1>
            <a href="/somewhere">Anker</a>
        </body>
    </html>
    """

    respx.get(target_url_1).mock(
        return_value=httpx.Response(
            200,
            text=page_content_1,
        )
    )
    respx.get(target_url_2).mock(
        return_value=httpx.Response(
            200,
            text=page_content_2,
        )
    )

    # basic html
    resp = httpx.get(target_url_1, follow_redirects=False)
    page = Html(Response(resp).content, target_url_1)

    assert page.soup is not None
    assert page.soup.find("title").get_text() == "Foobar"

    # base tag
    resp = httpx.get(target_url_2, follow_redirects=False)
    page = Html(Response(resp).content, target_url_2)

    assert page.soup is not None
    assert page.base_url == "https://example.com/"
    assert page.soup.find("title").get_text() == "Foobar"


@respx.mock
def test_iter_frame_page():
    target_url_1 = "http://perdu.com/"

    page_content_1 = """
    <html>
        <head>
            <title>Foobar</title>
        </head>
        <body>
            <iframe id="inlineFrameExample"
                title="Inline Frame Example"
                width="300"
                height="200"
                src="http://example.com">
            </iframe>
        </body>
    </html>
    """

    respx.get(target_url_1).mock(
        return_value=httpx.Response(
            200,
            text=page_content_1,
        )
    )

    # basic html
    resp = httpx.get(target_url_1, follow_redirects=False)
    page = Html(Response(resp).content, target_url_1)

    assert next(page.iter_frames()) == "http://example.com/"


@respx.mock
def test_redirection_url_page():
    target_url_1 = "http://perdu.com/"
    target_url_2 = "http://perdu2.com/"
    target_url_3 = "http://perdu3.com/"

    page_content = """
    <html>
        <head>
            <title>Foobar</title>
        </head>
        <body>

        </body>
    </html>
    """

    respx.get(target_url_1).mock(
        return_value=httpx.Response(
            200,
            text=page_content,
        )
    )

    respx.get(target_url_2).mock(
        return_value=httpx.Response(
            302,
            text=page_content,
            headers=[("Location", "index.html")],
        )
    )

    respx.get(target_url_3).mock(
        return_value=httpx.Response(
            302,
            text=page_content,
            headers=[("Location", "http://perdu3.com/")],
        )
    )

    # No redirect
    resp = httpx.get(target_url_1, follow_redirects=False)
    response = Response(resp)

    assert response.redirection_url == ""
    assert response.is_directory_redirection is False

    # Redirection
    resp = httpx.get(target_url_2, follow_redirects=False)
    response = Response(resp)

    assert response.redirection_url == "http://perdu2.com/index.html"
    assert response.is_directory_redirection is False

    # Same url
    resp = httpx.get(target_url_3, follow_redirects=False)
    response = Response(resp)

    assert response.redirection_url == "http://perdu3.com/"
    assert response.is_directory_redirection is True


@respx.mock
def test_is_directory_redirection_page():
    target_url_1 = "http://perdu.com/"
    target_url_2 = "http://perdu2.com/"

    page_content = """
    <html>
        <head>
            <title>Foobar</title>
        </head>
        <body>

        </body>
    </html>
    """

    respx.get(target_url_1).mock(
        return_value=httpx.Response(
            200,
            text=page_content,
        )
    )

    respx.get(target_url_2).mock(
        return_value=httpx.Response(
            302,
            text=page_content,
            headers=[("Location", "index.html")],
        )
    )

    # No redirect
    resp = httpx.get(target_url_1, follow_redirects=False)
    page = Response(resp)

    assert page.redirection_url == ""

    # Redirection
    resp = httpx.get(target_url_2, follow_redirects=False)
    page = Response(resp)

    assert page.redirection_url == "http://perdu2.com/index.html"


@respx.mock
def test_title_page():
    target_url_1 = "http://perdu.com/"

    page_content_1 = """
    <html>
        <head>
            <title>Foobar</title>
        </head>
        <body>
            <h1>Perdu sur l'Internet ?</h1>
        </body>
    </html>
    """

    respx.get(target_url_1).mock(
        return_value=httpx.Response(
            200,
            text=page_content_1,
        )
    )

    # basic html
    resp = httpx.get(target_url_1, follow_redirects=False)
    page = Html(Response(resp).content, target_url_1)

    assert page.soup is not None
    assert page.title == "Foobar"


@respx.mock
def test_html_redirection():
    target_url_1 = "http://perdu.com/"
    target_url_2 = "http://perdu2.com/"
    target_url_3 = "http://perdu3.com/"

    page_content_1 = """
    <!DOCTYPE html>
    <html>
        <head>
            <meta http-equiv="refresh" content="0;url=http://test.com/" />
            <title>Foobar</title>
        </head>
        <body>
            <h1>Perdu sur l'Internet ?</h1>
        </body>
    </html>
    """

    page_content_2 = """
    <!DOCTYPE html>
    <html>
        <head>
            <meta http-equiv="refresh" content="0;url='http://test.com/'" />
            <title>Foobar</title>
        </head>
        <body>
            <h1>Perdu sur l'Internet ?</h1>
        </body>
    </html>
    """

    page_content_3 = """
    <!DOCTYPE html>
    <html>
        <head>
            <meta http-equiv="refresh" content='0;url="http://test.com/"' />
            <title>Foobar</title>
        </head>
        <body>
            <h1>Perdu sur l'Internet ?</h1>
        </body>
    </html>
    """
    target_urls = [target_url_1, target_url_2, target_url_3]
    page_contents = [page_content_1, page_content_2, page_content_3]

    for (target_url, page_content) in zip(target_urls, page_contents):
        respx.get(target_url).mock(
            return_value=httpx.Response(
                200,
                text=page_content,
            )
        )

        resp = httpx.get(target_url, follow_redirects=False)
        page = Html(Response(resp).content, target_url)

        assert len(page.html_redirections) == 1
        assert page.html_redirections[0] == "http://test.com/"
