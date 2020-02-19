from bs4 import BeautifulSoup
import responses
import requests

from wapitiCore.net.xss_utils import get_context, has_csp, valid_xss_content_type
from wapitiCore.net.crawler import Page


def test_title_context():
    html = """<html>
    <head><title><strong>injection</strong></title>
    <body>
    </body>
    </html>"""

    soup = BeautifulSoup(html, "html.parser")
    assert get_context(soup, "injection") == [
        {"non_exec_parent": "title", "parent": "strong", "type": "text"}
    ]


def test_noscript_context():
    html = """<html>
    <head><title>Hello there</title>
    <body>
    <noscript>
    <textarea>
    <a href="injection">General Kenobi</a>
    <textarea>
    </noscript>
    </body>
    </html>"""

    soup = BeautifulSoup(html, "html.parser")
    assert get_context(soup, "injection") == [
        {"non_exec_parent": "noscript", "tag": "a", "name": "href", "type": "attrval"}
    ]


def test_comment_context():
    html = """<html>
    <head><title>Hello there</title>
    <body>
    <!--
    <noscript>
    <textarea>
    <a href="injection">General Kenobi</a>
    <textarea>
    </noscript>
    -->
    </body>
    </html>"""

    soup = BeautifulSoup(html, "html.parser")
    assert get_context(soup, "injection") == [
        {"non_exec_parent": "", "parent": "body", "type": "comment"}
    ]


def test_comment_in_noscript_context():
    html = """<html>
    <head><title>Hello there</title>
    <body>
    <noscript>
    <textarea>
    <!--
    <a href="injection">General Kenobi</a>
    -->
    <textarea>
    </noscript>
    </body>
    </html>"""

    soup = BeautifulSoup(html, "html.parser")
    assert get_context(soup, "injection") == [
        {"non_exec_parent": "noscript", "parent": "textarea", "type": "comment"}
    ]


def test_attrname_context():
    html = """<html>
    <head><title>Hello there</title>
    <body>
    <noembed>
    <input type=checkbox injection/>
    </noembed>
    </body>
    </html>"""

    soup = BeautifulSoup(html, "html.parser")
    assert get_context(soup, "injection") == [
        {"non_exec_parent": "noembed", "tag": "input", "type": "attrname", "name": "injection"}
    ]


def test_tagname_context():
    html = """<html>
    <head><title>Hello there</title>
    <body>
    <injection type=text name=username />
    </body>
    </html>"""

    soup = BeautifulSoup(html, "html.parser")
    assert get_context(soup, "injection") == [
        {"non_exec_parent": "", "type": "tag", "value": "injection"}
    ]


def test_partial_tagname_context():
    html = """<html>
    <head>
    <body>
    <noinjection>Hello there<noinjection>
    </body>
    </html>"""

    soup = BeautifulSoup(html, "html.parser")
    assert get_context(soup, "injection") == [
        {"non_exec_parent": "", "type": "tag", "value": "noinjection"}
    ]


@responses.activate
def test_csp_detection():
    url = "http://perdu.com/"
    responses.add(
        responses.GET,
        url,
        status=200,
        adding_headers={
            "Content-Type": "text/html"
        }
    )

    resp = requests.get(url)
    page = Page(resp, url)
    assert not has_csp(page)

    url = "http://perdu.com/http_csp"
    responses.add(
        responses.GET,
        url,
        status=200,
        adding_headers={
            "Content-Type": "text/html",
            "Content-Security-Policy": "blahblah;"
        }
    )

    resp = requests.get(url)
    page = Page(resp, url)
    assert has_csp(page)

    url = "http://perdu.com/meta_csp"
    responses.add(
        responses.GET,
        url,
        status=200,
        adding_headers={
            "Content-Type": "text/html"
        },
        body="""<html>
        <head>
        <meta http-equiv="Content-Security-Policy" content="default-src 'self'; img-src https://*; child-src 'none';">
        </head>
        <body>Hello there</body>
        </html>"""
    )

    resp = requests.get(url)
    page = Page(resp, url)
    assert has_csp(page)


@responses.activate
def test_valid_content_type():
    url = "http://perdu.com/"
    responses.add(
        responses.GET,
        url,
        status=200,
        adding_headers={
            "Content-Type": "text/html"
        }
    )

    resp = requests.get(url)
    page = Page(resp, url)
    assert valid_xss_content_type(page)

    url = "http://perdu.com/picture.png"
    responses.add(
        responses.GET,
        url,
        status=200,
        adding_headers={
            "Content-Type": "image/png"
        }
    )

    resp = requests.get(url)
    page = Page(resp, url)
    assert not valid_xss_content_type(page)
