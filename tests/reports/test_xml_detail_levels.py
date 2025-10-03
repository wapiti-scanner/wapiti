"""
Test XML report generation with different detail levels to ensure proper handling
of missing 'response' keys in crawled pages and vulnerability details.

This addresses issue #663: KeyError: 'response' in XML Report Generator
"""
from time import gmtime
import tempfile

import httpx

from wapitiCore.report.xmlreportgenerator import XMLReportGenerator
from wapitiCore.net.sql_persister import Response
from wapitiCore.net import Request
from wapitiCore.definitions import vulnerabilities, flatten_references


def test_xml_detail_report_level_2_full():
    """Test XML report generation with detailed_report_level=2 (full details including responses)"""
    report_gen = XMLReportGenerator()

    # Create crawled pages with response data (as they would be at level 2)
    crawled_pages = [
        {
            "response": {
                "status_code": 200,
                "headers": [["Content-Type", "text/html"]],
                "body": "<html>Page 1</html>"
            }
        },
        {
            "response": {
                "status_code": 404,
                "headers": [["Content-Type", "text/plain"]],
                "body": "Not Found"
            }
        }
    ]

    report_gen.set_report_info(
        "http://example.com",
        "folder",
        gmtime(),
        "WAPITI_VERSION",
        None,
        crawled_pages,
        2,
        2  # detailed_report_level = 2
    )

    for vul in vulnerabilities:
        report_gen.add_vulnerability_type(
            vul.name(),
            vul.description(),
            vul.solution(),
            flatten_references(vul.references())
        )

    request = Request("http://example.com/test?param=value")
    response = Response(
        httpx.Response(
            status_code=200,
            headers=httpx.Headers([["Content-Type", "text/html"]]),
            content=b"<html>Vulnerable</html>"
        ),
        url="http://example.com/test?param=value"
    )

    report_gen.add_vulnerability(
        "xss",
        "Reflected Cross Site Scripting",
        request=request,
        response=response,
        parameter="param",
        info="XSS found"
    )

    temp_obj = tempfile.NamedTemporaryFile(delete=False, suffix=".xml")
    output = temp_obj.name

    # This should not raise KeyError
    report_gen.generate_report(output)

    # Verify the XML contains expected data (string search, not strict parsing due to xsi namespace issue)
    with open(output) as fd:
        xml_content = fd.read()

        # Should have crawled pages with responses
        assert "<crawled_pages>" in xml_content
        assert "<response>" in xml_content
        assert "<status_code>200</status_code>" in xml_content
        assert "<html>Page 1</html>" in xml_content

        # Should have vulnerability with detail section at level 2
        assert "<detail>" in xml_content
        assert "<html>Vulnerable</html>" in xml_content


def test_xml_detail_report_level_1_light():
    """Test XML report generation with detailed_report_level=1 (crawled pages without response data)

    This is the main test case for issue #663 - when crawled_pages exist but don't have 'response' key.
    """
    report_gen = XMLReportGenerator()

    # Create crawled pages WITHOUT response data (as they would be at level 1)
    crawled_pages = [
        {"url": "http://example.com/page1"},
        {"url": "http://example.com/page2"}
    ]

    report_gen.set_report_info(
        "http://example.com",
        "folder",
        gmtime(),
        "WAPITI_VERSION",
        None,
        crawled_pages,
        2,
        1  # detailed_report_level = 1
    )

    for vul in vulnerabilities:
        report_gen.add_vulnerability_type(
            vul.name(),
            vul.description(),
            vul.solution(),
            flatten_references(vul.references())
        )

    request = Request("http://example.com/test?param=value")
    # Note: at level 1, vulnerabilities don't have detail section added

    report_gen.add_vulnerability(
        "xss",
        "Reflected Cross Site Scripting",
        request=request,
        parameter="param",
        info="XSS found"
    )

    temp_obj = tempfile.NamedTemporaryFile(delete=False, suffix=".xml")
    output = temp_obj.name

    # This should NOT raise KeyError: 'response' (the bug we're fixing)
    report_gen.generate_report(output)

    # Verify the XML contains expected sections
    with open(output) as fd:
        xml_content = fd.read()

        # Should have crawled pages section at level 1
        assert "<crawled_pages>" in xml_content
        assert "</crawled_pages>" in xml_content

        # But should NOT have response sections (since response key was missing)
        # Count response tags - should be 0 in crawled_pages, may be in other sections
        crawled_section_start = xml_content.find("<crawled_pages>")
        crawled_section_end = xml_content.find("</crawled_pages>")
        crawled_section = xml_content[crawled_section_start:crawled_section_end]
        assert "<response>" not in crawled_section, "Crawled pages should not have response at level 1"

        # Vulnerability should NOT have detail section at level 1
        vuln_section_start = xml_content.find("<vulnerability")
        if vuln_section_start > 0:
            vuln_section_end = xml_content.find("</vulnerability>", vuln_section_start)
            vuln_section = xml_content[vuln_section_start:vuln_section_end]
            assert "<detail>" not in vuln_section, "Vulnerability should not have detail at level 1"


def test_xml_detail_report_level_0_none():
    """Test XML report generation with detailed_report_level=0 (no details at all)"""
    report_gen = XMLReportGenerator()

    report_gen.set_report_info(
        "http://example.com",
        "folder",
        gmtime(),
        "WAPITI_VERSION",
        None,
        [],  # No crawled pages at level 0
        5,
        0  # detailed_report_level = 0
    )

    for vul in vulnerabilities:
        report_gen.add_vulnerability_type(
            vul.name(),
            vul.description(),
            vul.solution(),
            flatten_references(vul.references())
        )

    request = Request("http://example.com/test?param=value")

    report_gen.add_vulnerability(
        "xss",
        "Reflected Cross Site Scripting",
        request=request,
        parameter="param",
        info="XSS found"
    )

    temp_obj = tempfile.NamedTemporaryFile(delete=False, suffix=".xml")
    output = temp_obj.name

    # This should not raise any errors
    report_gen.generate_report(output)

    # Verify the XML contains expected sections
    with open(output) as fd:
        xml_content = fd.read()

        # Should NOT have crawled_pages section at level 0
        assert "<crawled_pages>" not in xml_content

        # Vulnerability should NOT have detail section at level 0
        assert "<detail>" not in xml_content


def test_xml_mixed_crawled_pages_with_and_without_response():
    """Test XML report with mixed crawled pages - some with response, some without.

    This edge case could occur if there's inconsistent data.
    """
    report_gen = XMLReportGenerator()

    # Mixed crawled pages - some with response, some without
    crawled_pages = [
        {
            "response": {
                "status_code": 200,
                "headers": [["Content-Type", "text/html"]],
                "body": "<html>Page 1</html>"
            }
        },
        {
            "url": "http://example.com/page2"  # No response key
        },
        {
            "response": None  # Explicit None
        }
    ]

    report_gen.set_report_info(
        "http://example.com",
        "folder",
        gmtime(),
        "WAPITI_VERSION",
        None,
        crawled_pages,
        3,
        2
    )

    for vul in vulnerabilities:
        report_gen.add_vulnerability_type(
            vul.name(),
            vul.description(),
            vul.solution(),
            flatten_references(vul.references())
        )

    request = Request("http://example.com/test")
    report_gen.add_vulnerability(
        "xss",
        "Reflected Cross Site Scripting",
        request=request,
        parameter="param",
        info="XSS found"
    )

    temp_obj = tempfile.NamedTemporaryFile(delete=False, suffix=".xml")
    output = temp_obj.name

    # Should handle mixed data gracefully without KeyError
    report_gen.generate_report(output)

    # Verify the XML is well-formed
    with open(output) as fd:
        xml_content = fd.read()

        # Should have crawled pages section
        assert "<crawled_pages>" in xml_content

        # Count response tags in crawled_pages section
        crawled_section_start = xml_content.find("<crawled_pages>")
        crawled_section_end = xml_content.find("</crawled_pages>")
        crawled_section = xml_content[crawled_section_start:crawled_section_end]

        # Should have exactly 1 response (only the first entry had valid response data)
        response_count = crawled_section.count("<response>")
        assert response_count == 1, f"Should only have 1 response for entries with valid response data, got {response_count}"
