import responses
import requests
import pytest

from wapitiCore.net.xss_utils import get_context_list, has_csp, valid_xss_content_type, meet_requirements
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
            "events": set(),
            "special_attributes": {"href"}
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
        {
            "non_exec_parent": "noembed",
            "tag": "input",
            "type": "attrname",
            "name": "injection",
            "events": set(),
            "special_attributes": {"type=checkbox"}
        }
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
            "events": {"onclick"},
            "special_attributes": {"href"}
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
            'type': 'attrval',
            "special_attributes": {"href"}
        },
        {'non_exec_parent': '', 'parent': 'body', 'type': 'comment'},
        {
            'events': set(),
            'name': 'injection',
            'non_exec_parent': '',
            'tag': 'input',
            'type': 'attrname',
            "special_attributes": {"type=checkbox"}
        },
        {'non_exec_parent': 'noscript', 'parent': 'b', 'type': 'text'}
    ]


def test_similar_contexts():
    html = """<html>
    <body>
    <a href="injection">Hello there</a>
    <a href="injection2">General Kenobi</a>
    </body>
    </html>"""

    assert get_context_list(html, "injection") == [
        {
            "type": "attrval",
            "name": "href",
            "tag": "a",
            "events": set(),
            "separator": "\"",
            "non_exec_parent": "",
            "special_attributes": {"href"}
        }
    ]


def test_different_separator_contexts():
    html = """<html>
    <body>
    <a href="injection">Hello there</a>
    <a href='injection2'>General Kenobi</a>
    </body>
    </html>"""

    assert get_context_list(html, "injection") == [
        {
            "type": "attrval",
            "name": "href",
            "tag": "a",
            "events": set(),
            "separator": "\"",
            "non_exec_parent": "",
            "special_attributes": {"href"}
        },
        {
            "type": "attrval",
            "name": "href",
            "tag": "a",
            "events": set(),
            "separator": "'",
            "non_exec_parent": "",
            "special_attributes": {"href"}
        }
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
    page = Page(resp)
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
    page = Page(resp)
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
    page = Page(resp)
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
    page = Page(resp)
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
    page = Page(resp)
    assert not valid_xss_content_type(page)


def test_payload_requirements():
    code = '<input type="hidden" value="injected"/>'
    context_list = get_context_list(code, "injected")
    assert context_list[0]["special_attributes"] == {"type=hidden"}
    with pytest.raises(RuntimeError):
        # Requirement not met due to type being "hidden"
        meet_requirements(["!style", "type!=hidden"], context_list[0]["special_attributes"])

    code = '<input type="text" value="injected" style="imgroot" />'
    context_list = get_context_list(code, "injected")
    assert context_list[0]["special_attributes"] == {"style", "type=text"}
    with pytest.raises(RuntimeError):
        # Requirement not met due to style being present
        meet_requirements(["!style", "type!=hidden"], context_list[0]["special_attributes"])

    code = '<input type="text" value="injected"/>'
    context_list = get_context_list(code, "injected")
    assert context_list[0]["special_attributes"] == {"type=text"}
    # Requirement met as input type is not "hidden" and style is missing
    assert meet_requirements(["!style", "type!=hidden"], context_list[0]["special_attributes"]) is ""

    code = '<input value="injected"/>'
    context_list = get_context_list(code, "injected")
    # Requirement met as there is no special attributes to make our life harder
    assert "special_attributes" not in context_list[0]
    assert meet_requirements(["!style", "type!=hidden"], []) is ""
