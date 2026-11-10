#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
#
import time
import xml.dom.minidom as minidom
import xml.etree.ElementTree as ElementTree
from xml.dom import expatbuilder

import httpx
import pytest

from wapitiCore.net import Request
from wapitiCore.net.response import Response
from wapitiCore.report.xmlreportgenerator import XMLReportGenerator

AUTH = {
    "url": "http://example.com/login",
    "logged_in": True,
    "form": {"login_field": "user", "password_field": "pass"},
}

# Ordinary authenticated body, no terminator: its serialized form must not change.
ORDINARY_BODY = "<html><body><p>a &amp; b</p><script>x < 1 && y > 2</script></body></html>"


def _generate(path, body=ORDINARY_BODY, desc="description", sol="solution", auth=AUTH,
              level=2, url="http://example.com/?id=1", crawled_pages=None):
    generator = XMLReportGenerator()
    generator.set_report_info(
        "http://example.com/", "folder", time.gmtime(0), "WAPITI_VERSION", auth,
        crawled_pages or [], len(crawled_pages or []), level,
    )
    generator.add_vulnerability_type("SQL Injection", desc, sol, {"title": "url"}, None)
    raw = httpx.Response(
        200, headers={"content-type": "text/html; charset=utf-8"}, content=body.encode()
    )
    generator.add_vulnerability(
        module="sql", category="SQL Injection", level=3, request=Request(url),
        parameter="id", info="info", wstg=None,
        response=Response(raw, url="http://example.com/page"),
    )
    generator.generate_report(path)


def _node_texts(path, tag):
    """Character data of every element named tag, through ElementTree."""
    return [element.text for element in ElementTree.parse(path).iter(tag)]


def _dom_elements(path, tag):
    return minidom.parse(path).getElementsByTagName(tag)


def _dom_text(element):
    return "".join(
        child.data for child in element.childNodes
        if child.nodeType in (child.TEXT_NODE, child.CDATA_SECTION_NODE)
    )


def _single_node_type(path, tag):
    element = _dom_elements(path, tag)[-1]
    assert len(element.childNodes) == 1
    return element.childNodes[0].nodeType


# A value carrying the terminator reaches the report through a real response body,
# a real flaw description and a real flaw solution.
TERMINATOR_BODIES = {
    "single": "<p>before ]]> after</p>",
    "multiple": "<p>a]]>b]]>c</p>",
    "only_terminator": "]]>",
    "utf8_lf": "<p>中文 é\nsecond line ]]>\nthird line</p>",
    "metacharacters": "<a href='x?y=1&amp;z=2'>&lt;tag&gt; ]]> &amp;</a>",
}


@pytest.mark.parametrize("body", TERMINATOR_BODIES.values(), ids=TERMINATOR_BODIES.keys())
def test_response_body_with_terminator_is_parsed_back_unchanged(tmp_path, body):
    """A body holding "]]>" must be written and read back without losing any character."""
    path = str(tmp_path / "report.xml")
    _generate(path, body=body)

    assert path and open(path, "rb").read()
    # Both parsers must give back the exact logical body.
    assert _node_texts(path, "body")[-1] == body
    assert _dom_text(_dom_elements(path, "body")[-1]) == body
    # The fallback node is a text node: minidom cannot hold this sequence in CDATA.
    assert _single_node_type(path, "body") == minidom.Node.TEXT_NODE


@pytest.mark.parametrize(
    "tag, kwargs",
    [("description", {"desc": "before ]]> after"}), ("solution", {"sol": "first ]]> second"})],
    ids=["description", "solution"],
)
def test_description_and_solution_with_terminator_are_parsed_back(tmp_path, tag, kwargs):
    """The flaw type description and solution are written and read back unchanged."""
    path = str(tmp_path / "report.xml")
    _generate(path, **kwargs)
    expected = list(kwargs.values())[0]

    assert _node_texts(path, tag)[0] == expected
    assert _dom_text(_dom_elements(path, tag)[0]) == expected
    assert _single_node_type(path, tag) == minidom.Node.TEXT_NODE


def test_crawled_page_body_with_terminator(tmp_path):
    """A crawled page body goes through the same CDATA node at detail level 2."""
    # Same shape as SqlPersister.get_crawled_paths_level_2(); not a real database run.
    crawled_pages = [{
        "path": "http://example.com/crawled",
        "response": {
            "status_code": 200,
            "body": "<p>crawled ]]> page</p>",
            "headers": [("content-type", "text/html")],
        },
    }]
    path = str(tmp_path / "report.xml")
    _generate(path, crawled_pages=crawled_pages)

    bodies = _node_texts(path, "body")
    # The crawled pages section is written before the vulnerability entries.
    assert len(bodies) == 2
    assert bodies[0] == "<p>crawled ]]> page</p>"
    assert _dom_text(_dom_elements(path, "body")[0]) == "<p>crawled ]]> page</p>"


def test_ordinary_body_keeps_cdata_section_and_serialized_bytes(tmp_path):
    """Without the terminator the CDATA section and its exact serialized bytes are kept."""
    path = str(tmp_path / "report.xml")
    _generate(path)

    assert _single_node_type(path, "body") == minidom.Node.CDATA_SECTION_NODE
    # The body is written verbatim inside a CDATA section, not escaped text.
    serialized = open(path, encoding="utf-8").read()
    assert "<![CDATA[" + ORDINARY_BODY + "]]>" in serialized
    assert _node_texts(path, "body")[-1] == ORDINARY_BODY
    assert _dom_text(_dom_elements(path, "body")[-1]) == ORDINARY_BODY
    # Ordinary generation stays deterministic byte for byte.
    second = str(tmp_path / "report2.xml")
    _generate(second)
    assert open(path, "rb").read() == open(second, "rb").read()


def test_auth_none_report_serializes_without_namespace_repair(tmp_path):
    """auth=None: the report is written to completion and its ordinary body text is kept.

    The unbound xsi prefix of this pre-existing state is tracked separately, so nothing here
    requires it to be declared, repaired or rejected: the file is read with namespace
    processing off and only the serialization result is asserted.
    """
    path = str(tmp_path / "report.xml")
    _generate(path, auth=None)

    # The report runs to completion and closes its root element.
    assert path and open(path, "rb").read()
    assert open(path, encoding="utf-8").read().rstrip().endswith("</report>")
    # Namespace-agnostic read: the document is accepted as it is written.
    document = expatbuilder.parse(path, namespaces=False)
    assert document.documentElement.tagName == "report"
    bodies = document.getElementsByTagName("body")
    assert bodies
    assert _dom_text(bodies[-1]) == ORDINARY_BODY


def test_request_and_curl_values_cannot_carry_the_literal_terminator(tmp_path):
    """A URL input is percent-encoded, so these two sites stay CDATA: an encoding boundary."""
    path = str(tmp_path / "report.xml")
    _generate(path, url="http://example.com/?id=pre%5D%5D%3Epost")

    request_text = _node_texts(path, "http_request")[0]
    assert "%5D%5D%3E" in request_text
    assert "]]>" not in request_text
    curl_text = _node_texts(path, "curl_command")[0]
    assert "%5D%5D%3E" in curl_text
    assert "]]>" not in curl_text
