import responses
import requests

from wapitiCore.net.xss_utils import get_context_list, has_csp, valid_xss_content_type
from wapitiCore.net.crawler import Page


def test_title_context():
    html = """<html>
    <head><title><strong>injection</strong></title>
    <body>
    </body>
    </html>"""

    assert get_context_list(html, "injection") == [
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

    assert get_context_list(html, "injection") == [
        {
            "non_exec_parent": "noscript",
            "tag": "a",
            "name": "href",
            "type": "attrval",
            "separator": "\"",
            "events": set()
        }
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

    assert get_context_list(html, "injection") == [
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

    assert get_context_list(html, "injection") == [
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

    assert get_context_list(html, "injection") == [
        {"non_exec_parent": "noembed", "tag": "input", "type": "attrname", "name": "injection", "events": set()}
    ]


def test_tagname_context():
    html = """<html>
    <head><title>Hello there</title>
    <body>
    <injection type=text name=username />
    </body>
    </html>"""

    assert get_context_list(html, "injection") == [
        {"non_exec_parent": "", "type": "tag", "value": "injection", "events": set()}
    ]


def test_partial_tagname_context():
    html = """<html>
    <head>
    <body>
    <noinjection>Hello there<noinjection>
    </body>
    </html>"""

    assert get_context_list(html, "injection") == [
        {"non_exec_parent": "", "type": "tag", "value": "noinjection", "events": set()}
    ]


def test_attr_value_single_quote_and_event_context():
    html = """<html>
    <head><title>Hello there</title>
    <body>
    <a href='injection' onclick='location.href="index.html"';>General Kenobi</a>
    </body>
    </html>"""

    assert get_context_list(html, "injection") == [
        {
            "non_exec_parent": "",
            "tag": "a",
            "name": "href",
            "type": "attrval",
            "separator": "'",
            "events": {"onclick"}
        }
    ]


def test_multiple_contexts():
    html = """<html>
    <head><title>Hello injection</title>
    <body>
    <a href="injection">General Kenobi</a>
    <!-- injection -->
    <input type=checkbox injection />
    <noscript><b>injection</b></noscript>
    </body>
    </html>"""

    assert get_context_list(html, "injection") == [
        {'non_exec_parent': 'title', 'parent': 'title', 'type': 'text'},
        {
            'events': set(),
            'name': 'href',
            'non_exec_parent': '',
            'separator': '"',
            'tag': 'a',
            'type': 'attrval'
        },
        {'non_exec_parent': '', 'parent': 'body', 'type': 'comment'},
        {
            'events': set(),
            'name': 'injection',
            'non_exec_parent': '',
            'tag': 'input',
            'type': 'attrname'
        },
        {'non_exec_parent': 'noscript', 'parent': 'b', 'type': 'text'}
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


if __name__ == "__main__":
    test_attr_value_single_quote_and_event_context()
