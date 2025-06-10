from typing import List

import httpx
import pytest

from wapitiCore.attack.modules.passive.mod_csp import (
    ModuleCsp,
    MSG_NO_CSP,
    MSG_CSP_MISSING,
    MSG_CSP_UNSAFE,
)
from wapitiCore.definitions.csp import CspFinding
from wapitiCore.language.vulnerability import MEDIUM_LEVEL, LOW_LEVEL
from wapitiCore.net import Response, Request
from wapitiCore.net.csp_utils import csp_header_to_dict, check_policy_values


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
        # CSP declared but object-src is missing
        (
            {
                "Content-Type": "text/html",
                "Content-Security-Policy": "default-src 'self'",
            },
            [MSG_CSP_UNSAFE.format("object-src", "http://example.com")],
            [MEDIUM_LEVEL],
        ),
        # CSP declared but script-src contains unsafe-inline. Also as default-src is missing, there are no fallback
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
            ],
            [LOW_LEVEL, MEDIUM_LEVEL, MEDIUM_LEVEL, MEDIUM_LEVEL],
        ),
        # CSP is well-made
        (
            {
                "Content-Type": "text/html",
                "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'",
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
