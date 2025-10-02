from typing import List

import httpx
import pytest

from wapitiCore.attack.modules.passive.mod_csp import (
    ModuleCsp,
    MSG_NO_CSP,
    MSG_CSP_MISSING,
    MSG_CSP_UNSAFE,
    MSG_CSP_INVALID_DIRECTIVE,
)
from wapitiCore.definitions.csp import CspFinding
from wapitiCore.language.vulnerability import MEDIUM_LEVEL, LOW_LEVEL, HIGH_LEVEL
from wapitiCore.net import Response, Request
from wapitiCore.net.csp_utils import (
    csp_header_to_dict,
    check_policy_values,
    get_invalid_directives,
    VALID_CSP_DIRECTIVES,
)


def test_csp_parsing():
    csp_dict = csp_header_to_dict(
        "script-src 'self' 'unsafe-inline' data: http://*.fr ; object-src 'none' '';"
    )
    assert csp_dict.keys() == {"script-src", "object-src"}
    assert set(csp_dict["script-src"]) == {
        "self",
        "unsafe-inline",
        "data:",
        "http://*.fr",
    }
    assert set(csp_dict["object-src"]) == {"none", ""}


def test_bad_csp_examples():
    # Some examples from https://www.slideshare.net/LukasWeichselbaum/breaking-bad-csp
    # May be useful too: https://www.netsparker.com/blog/web-security/negative-impact-incorrect-csp-implementations/

    # unsafe-inline script
    csp_dict = csp_header_to_dict(
        "script-src 'self' 'unsafe-inline'; object-src 'none';"
    )
    assert check_policy_values("script-src", csp_dict) == 0

    # URL schemes
    csp_dict = csp_header_to_dict("script-src 'self' https:; object-src 'none' ;")
    assert check_policy_values("script-src", csp_dict) == 0

    # wildcard
    csp_dict = csp_header_to_dict("script-src 'self' *; object-src 'none' ;")
    assert check_policy_values("script-src", csp_dict) == 0


def test_missing_csp_directive():
    csp_dict = csp_header_to_dict("script-src 'self'")
    assert check_policy_values("default-src", csp_dict) == -1


def test_valid_csp_directives():
    """Test that all standard CSP directives are recognized as valid."""
    standard_directives = [
        "default-src", "script-src", "style-src", "img-src", "font-src",
        "connect-src", "media-src", "object-src", "frame-src", "sandbox",
        "report-uri", "child-src", "form-action", "frame-ancestors",
        "plugin-types", "base-uri", "report-to", "worker-src", "manifest-src",
        "prefetch-src", "navigate-to", "upgrade-insecure-requests",
        "block-all-mixed-content", "require-sri-for", "require-trusted-types-for",
        "trusted-types", "script-src-elem", "script-src-attr", "style-src-elem",
        "style-src-attr"
    ]

    for directive in standard_directives:
        assert directive in VALID_CSP_DIRECTIVES, f"{directive} should be valid"


def test_invalid_directive_detection():
    """Test detection of invalid/misspelled CSP directives."""
    csp_dict = csp_header_to_dict(
        "script-src 'self'; foobar-src 'none'; scriptsrc 'self'; object-source 'none'"
    )
    invalid = get_invalid_directives(csp_dict)

    assert "foobar-src" in invalid
    assert "scriptsrc" in invalid
    assert "object-source" in invalid
    assert "script-src" not in invalid


def test_frame_ancestors_directive():
    """Test frame-ancestors directive checking for clickjacking protection."""
    # Missing frame-ancestors
    csp_dict = csp_header_to_dict("default-src 'self'")
    assert check_policy_values("frame-ancestors", csp_dict) == -1

    # Unsafe frame-ancestors (allows any)
    csp_dict = csp_header_to_dict("frame-ancestors *")
    assert check_policy_values("frame-ancestors", csp_dict) == 0

    # Safe frame-ancestors with 'none'
    csp_dict = csp_header_to_dict("frame-ancestors 'none'")
    assert check_policy_values("frame-ancestors", csp_dict) == 1

    # Safe frame-ancestors with 'self'
    csp_dict = csp_header_to_dict("frame-ancestors 'self'")
    assert check_policy_values("frame-ancestors", csp_dict) == 1


def test_form_action_directive():
    """Test form-action directive checking for form submission control."""
    # Missing form-action
    csp_dict = csp_header_to_dict("default-src 'self'")
    assert check_policy_values("form-action", csp_dict) == -1

    # Unsafe form-action (allows any)
    csp_dict = csp_header_to_dict("form-action *")
    assert check_policy_values("form-action", csp_dict) == 0

    # Safe form-action with 'none'
    csp_dict = csp_header_to_dict("form-action 'none'")
    assert check_policy_values("form-action", csp_dict) == 1

    # Safe form-action with 'self'
    csp_dict = csp_header_to_dict("form-action 'self'")
    assert check_policy_values("form-action", csp_dict) == 1


def test_upgrade_insecure_requests():
    """Test upgrade-insecure-requests directive detection."""
    # Missing upgrade-insecure-requests
    csp_dict = csp_header_to_dict("default-src 'self'")
    assert "upgrade-insecure-requests" not in csp_dict

    # Present upgrade-insecure-requests (it's a valueless directive)
    csp_dict = csp_header_to_dict("default-src 'self'; upgrade-insecure-requests")
    assert "upgrade-insecure-requests" in csp_dict


@pytest.fixture
def module():
    """Fixture that provides a fresh instance of the module for each test."""
    return ModuleCsp()


def create_mock_objects(
    url: str,
    method: str = "GET",
    get_params: List[List[str]] = None,
    post_params: List[List[str]] = None,
    request_headers: dict = None,
    response_status: int = 200,
    response_headers: dict = None,
    response_content: str = "",
):
    """Helper to create realistic Request and Response objects."""
    if request_headers is None:
        request_headers = {}
    if get_params is None:
        get_params = []
    if post_params is None:
        post_params = []
    if response_headers is None:
        response_headers = {}

    request = Request(
        path=url,
        method=method,
        get_params=get_params,
        post_params=post_params,
    )
    request.set_headers(httpx.Headers(request_headers))

    response_obj = httpx.Response(
        status_code=response_status,
        headers=response_headers,
        content=response_content.encode("utf-8"),
    )
    response = Response(url=url, response=response_obj)

    return request, response


def get_all_vulnerabilities(module, request, response):
    """Helper to get all vulnerabilities from the generator."""
    return list(module.analyze(request, response))


@pytest.mark.parametrize(
    "headers,expected_msgs,expected_severities",
    [
        # Content-Type is missing so CSP headers are ignored
        ({}, [], []),
        # Content-Type is not text/html => ignored
        ({"Content-Type": "application/json"}, [], []),
        # Content-Type is OK but CSP is not declared
        (
            {"Content-Type": "text/html"},
            [MSG_NO_CSP.format("http://example.com")],
            [LOW_LEVEL],
        ),
        # CSP declared but object-src is missing, now also checks base-uri, frame-ancestors and form-action
        (
            {
                "Content-Type": "text/html",
                "Content-Security-Policy": "default-src 'self'",
            },
            [
                MSG_CSP_UNSAFE.format("object-src", "http://example.com"),
                MSG_CSP_MISSING.format("base-uri", "http://example.com"),
                MSG_CSP_MISSING.format("frame-ancestors", "http://example.com"),
                MSG_CSP_MISSING.format("form-action", "http://example.com"),
            ],
            [MEDIUM_LEVEL, MEDIUM_LEVEL, HIGH_LEVEL, MEDIUM_LEVEL],
        ),
        # CSP declared but script-src contains unsafe-inline, now includes new directives
        (
            {
                "Content-Type": "text/html",
                "Content-Security-Policy": "script-src 'unsafe-inline'",
            },
            [
                MSG_CSP_MISSING.format("default-src", "http://example.com"),
                MSG_CSP_UNSAFE.format("script-src", "http://example.com"),
                MSG_CSP_MISSING.format("object-src", "http://example.com"),
                MSG_CSP_MISSING.format("base-uri", "http://example.com"),
                MSG_CSP_MISSING.format("frame-ancestors", "http://example.com"),
                MSG_CSP_MISSING.format("form-action", "http://example.com"),
            ],
            [LOW_LEVEL, MEDIUM_LEVEL, MEDIUM_LEVEL, MEDIUM_LEVEL, HIGH_LEVEL, MEDIUM_LEVEL],
        ),
        # CSP is well-made - now includes frame-ancestors and form-action
        (
            {
                "Content-Type": "text/html",
                "Content-Security-Policy": (
                    "default-src 'self'; script-src 'self'; object-src 'none'; "
                    "base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
                ),
            },
            [],
            [],
        ),
    ],
)
def test_module_csp_analyze(module, headers, expected_msgs, expected_severities):
    request, response = create_mock_objects(
        "http://example.com", response_headers=headers
    )

    vulns = list(module.analyze(request, response))

    assert len(vulns) == len(expected_msgs)

    for vuln, expected_msg, expected_sev in zip(
        vulns, expected_msgs, expected_severities
    ):
        assert vuln.finding_class == CspFinding
        assert vuln.info == expected_msg
        assert vuln.severity == expected_sev


def test_invalid_directives_in_csp(module):
    """Test detection of invalid/misspelled CSP directives."""
    request, response = create_mock_objects(
        "http://example.com",
        response_headers={
            "Content-Type": "text/html",
            "Content-Security-Policy": "script-src 'self'; foobar-src 'none'; object-src 'none'",
        },
    )

    vulns = list(module.analyze(request, response))

    # Should report the invalid directive
    invalid_directive_vulns = [v for v in vulns if "foobar-src" in v.info]
    assert len(invalid_directive_vulns) == 1
    assert invalid_directive_vulns[0].severity == MEDIUM_LEVEL


def test_missing_frame_ancestors(module):
    """Test detection of missing frame-ancestors directive."""
    request, response = create_mock_objects(
        "http://example.com",
        response_headers={
            "Content-Type": "text/html",
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'",
        },
    )

    vulns = list(module.analyze(request, response))

    # Should report missing frame-ancestors (HIGH severity for clickjacking protection)
    frame_ancestor_vulns = [v for v in vulns if "frame-ancestors" in v.info]
    assert len(frame_ancestor_vulns) == 1
    assert frame_ancestor_vulns[0].severity == HIGH_LEVEL


def test_unsafe_frame_ancestors(module):
    """Test detection of unsafe frame-ancestors directive."""
    request, response = create_mock_objects(
        "http://example.com",
        response_headers={
            "Content-Type": "text/html",
            "Content-Security-Policy": "default-src 'self'; frame-ancestors *",
        },
    )

    vulns = list(module.analyze(request, response))

    # Should report unsafe frame-ancestors
    frame_ancestor_vulns = [v for v in vulns if "frame-ancestors" in v.info and "not safe" in v.info]
    assert len(frame_ancestor_vulns) == 1
    assert frame_ancestor_vulns[0].severity == HIGH_LEVEL


def test_missing_form_action(module):
    """Test detection of missing form-action directive."""
    request, response = create_mock_objects(
        "http://example.com",
        response_headers={
            "Content-Type": "text/html",
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'",
        },
    )

    vulns = list(module.analyze(request, response))

    # Should report missing form-action
    form_action_vulns = [v for v in vulns if "form-action" in v.info]
    assert len(form_action_vulns) == 1
    assert form_action_vulns[0].severity == MEDIUM_LEVEL


def test_comprehensive_good_csp(module):
    """Test that a comprehensive, secure CSP doesn't trigger warnings."""
    request, response = create_mock_objects(
        "http://example.com",
        response_headers={
            "Content-Type": "text/html",
            "Content-Security-Policy": (
                "default-src 'self'; "
                "script-src 'self'; "
                "object-src 'none'; "
                "base-uri 'self'; "
                "frame-ancestors 'none'; "
                "form-action 'self'; "
                "upgrade-insecure-requests"
            ),
        },
    )

    vulns = list(module.analyze(request, response))

    # Should not report any vulnerabilities
    assert len(vulns) == 0


def test_multiple_issues_severity_prioritization(module):
    """Test that severity is correctly assigned when multiple issues exist."""
    request, response = create_mock_objects(
        "http://example.com",
        response_headers={
            "Content-Type": "text/html",
            "Content-Security-Policy": "script-src 'unsafe-inline'; foobar-src 'test'",
        },
    )

    vulns = list(module.analyze(request, response))

    # Should have multiple issues with appropriate severities
    assert len(vulns) > 0

    # Check that we have HIGH severity issues (missing frame-ancestors)
    high_severity_vulns = [v for v in vulns if v.severity == HIGH_LEVEL]
    assert len(high_severity_vulns) > 0
