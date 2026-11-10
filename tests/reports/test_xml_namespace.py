"""Namespace well-formedness of the XML report exported by XMLReportGenerator.

The generator writes ``xsi:nil="true"`` on the ``info[@name="auth"]`` element when
no authentication was used (the default scan path passes ``auth=None``).  The
prefix used by that attribute must be declared in the document, otherwise the
report is not namespace-well-formed and both ``xml.etree.ElementTree`` and
``xml.dom.minidom`` refuse to read the file back.

These tests only drive the real generator through ``set_report_info`` and
``generate_report`` and then read the produced file back with the standard
library parsers.  They do not reimplement the serialization logic.
"""

from time import gmtime
import xml.etree.ElementTree as ElementTree
from xml.dom import minidom

import pytest

from wapitiCore.report.xmlreportgenerator import XMLReportGenerator

XSI_NAMESPACE = "http://www.w3.org/2001/XMLSchema-instance"

AUTH_WITH_FORM = {
    "url": "http://perdu.com/login",
    "logged_in": True,
    "form": {
        "login_field": "username",
        "password_field": "password",
    },
}


def generate_report_file(tmp_path, auth):
    """Run the real generator over the given auth state and return (path, text)."""
    report_gen = XMLReportGenerator()
    report_gen.set_report_info(
        "http://perdu.com",
        "folder",
        gmtime(0),
        "WAPITI_VERSION",
        auth,
        [],
        0,
        1,
    )
    report_path = tmp_path / "report.xml"
    report_gen.generate_report(str(report_path))
    return report_path, report_path.read_text(encoding="utf-8", errors="ignore")


def minidom_auth_node(report_path):
    """Return the ``info[@name="auth"]`` element from a minidom parse of the report."""
    document = minidom.parse(str(report_path))
    for node in document.getElementsByTagName("info"):
        if node.getAttribute("name") == "auth":
            return node
    raise AssertionError("auth info element is missing from the exported report")


def elementtree_auth_node(report_text):
    """Return the ``info[@name="auth"]`` element from an ElementTree parse of the report."""
    root = ElementTree.fromstring(report_text)
    for node in root.iter("info"):
        if node.get("name") == "auth":
            return node
    raise AssertionError("auth info element is missing from the exported report")


def test_no_auth_report_is_namespace_well_formed(tmp_path):
    """auth=None is the default scan state; the exported report must parse."""
    report_path, report_text = generate_report_file(tmp_path, None)

    # Both standard consumers must accept the file.
    ElementTree.parse(str(report_path))
    document = minidom.parse(str(report_path))
    assert document.documentElement.tagName == "report"

    auth_node = elementtree_auth_node(report_text)
    assert auth_node.get(f"{{{XSI_NAMESPACE}}}nil") == "true"

    # The nil marker is kept as an XSI attribute, and the prefix is declared.
    assert minidom_auth_node(report_path).hasAttributeNS(XSI_NAMESPACE, "nil")
    assert 'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"' in report_text


def test_authenticated_report_keeps_auth_payload(tmp_path):
    """A full auth dictionary still exports its url, state and form fields."""
    report_path, report_text = generate_report_file(tmp_path, AUTH_WITH_FORM)

    ElementTree.parse(str(report_path))
    auth_node = minidom_auth_node(report_path)
    assert not auth_node.hasAttributeNS(XSI_NAMESPACE, "nil")

    url_node = auth_node.getElementsByTagName("url")[0]
    assert url_node.firstChild.nodeValue == AUTH_WITH_FORM["url"]
    logged_in_node = auth_node.getElementsByTagName("logged_in")[0]
    assert logged_in_node.firstChild.nodeValue == "true"

    form_node = auth_node.getElementsByTagName("form")[0]
    assert form_node.getElementsByTagName("login_field")[0].firstChild.nodeValue == "username"
    assert form_node.getElementsByTagName("password_field")[0].firstChild.nodeValue == "password"

    # No nil marker leaks into reports whose auth payload is not nil.
    assert "xsi:nil" not in report_text


@pytest.mark.parametrize("form", [None, {}])
def test_authenticated_report_without_form_stays_parseable(tmp_path, form):
    """Empty form credentials are not serialized as a nil form element."""
    auth = {"url": "http://perdu.com/login", "logged_in": False, "form": form}
    report_path, report_text = generate_report_file(tmp_path, auth)

    ElementTree.parse(str(report_path))
    auth_node = minidom_auth_node(report_path)
    assert not auth_node.hasAttributeNS(XSI_NAMESPACE, "nil")
    assert not auth_node.getElementsByTagName("form")
    assert "<form" not in report_text
