from bs4 import BeautifulSoup

from wapitiCore.net.xss_utils import get_context


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
