import pytest
from typing import List, Tuple, Union
from unittest.mock import MagicMock

import httpx

from wapitiCore.attack.modules.passive.mod_https_redirect import ModuleHttpsRedirect
from wapitiCore.net import Request
from wapitiCore.net.response import Response
from wapitiCore.language.vulnerability import LOW_LEVEL, MEDIUM_LEVEL
from wapitiCore.definitions.https_redirect import HstsFinding


log_red = MagicMock()
log_orange = MagicMock()


def create_response(
    status_code: int = 200,
    headers: Union[dict, List[Tuple[str, str]]] = None,
    url: str = "http://example.com/",
):
    """
    Helper to create a Response object from an httpx.Response object.
    """
    if headers is None:
        headers = {}

    httpx_headers = {}
    if isinstance(headers, list):
        for key, value in headers:
            httpx_headers[key] = value
    elif isinstance(headers, dict):
        httpx_headers = headers

    return Response(
        url=url,
        response=httpx.Response(
            status_code=status_code, headers=httpx_headers, content=b""
        ),
    )


@pytest.fixture
def module():
    """Fixture that provides a fresh instance of the module for each test."""
    return ModuleHttpsRedirect()


def create_mock_objects(
    url: str,
    method: str = "GET",
    get_params: List[List[str]] = None,
    post_params: List[List[str]] = None,
    request_headers: dict = None,
    response_status: int = 200,
    response_headers: dict = None,
    redirection_url: str = None,
):
    """
    Helper to create more realistic Request and Response objects.
    """
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

    if redirection_url:
        response_headers["Location"] = redirection_url
        response_obj = httpx.Response(
            status_code=response_status, headers=response_headers, content=b""
        )
    else:
        response_obj = httpx.Response(
            status_code=response_status, headers=response_headers, content=b""
        )

    response = Response(url=url, response=response_obj)

    return request, response


def test_non_sensitive_http_no_redirect(module):
    """
    Test a non-sensitive HTTP request without redirection.
    A LOW level vulnerability is expected.
    """
    request, response = create_mock_objects(
        "http://test.com/index.html", response_headers={"Content-Type": "text/html"}
    )
    vuln = next(module.analyze(request, response), None)

    assert vuln is not None
    assert (
        vuln.info
        == "No HTTPS redirection for this host. All HTTP requests are served in clear text."
    )
    assert vuln.severity == LOW_LEVEL
    assert vuln.finding_class == HstsFinding


def test_non_sensitive_http_redirect_to_https(module):
    """
    Test a non-sensitive HTTP request with a redirection to HTTPS.
    No vulnerability is expected.
    """
    request, response = create_mock_objects(
        "http://test.com/index.html",
        response_status=301,
        redirection_url="https://test.com/index.html",
        response_headers={"Location": "https://test.com/index.html"},
    )
    vuln = next(module.analyze(request, response), None)

    assert vuln is None


def test_sensitive_http_get_params_no_redirect(module):
    """
    Test a sensitive HTTP request (GET parameters) with no redirection.
    A MEDIUM level vulnerability is expected.
    """
    request, response = create_mock_objects(
        "http://test.com/page?p=1",
        get_params=[["p", "1"]],
        response_headers={"Content-Type": "text/html"},
    )
    vuln = next(module.analyze(request, response), None)

    assert vuln is not None
    expected_info = (
        "Sensitive data (GET parameters) was sent over an unencrypted HTTP connection to http://test.com/page?p=1. "
        "The server did not enforce HTTPS."
    )
    assert vuln.info == expected_info
    assert vuln.severity == MEDIUM_LEVEL
    assert vuln.finding_class == HstsFinding


def test_sensitive_http_post_no_redirect(module):
    """
    Test a sensitive HTTP request (POST data) with no redirection.
    A MEDIUM level vulnerability is expected.
    """
    request, response = create_mock_objects(
        "http://test.com/submit",
        method="POST",
        post_params=[["p", "1"]],
        response_headers={"Content-Type": "text/html"},
    )
    vuln = next(module.analyze(request, response), None)

    assert vuln is not None
    expected_info = (
        "Sensitive data (POST data) was sent over an unencrypted HTTP connection to http://test.com/submit. "
        "The server did not enforce HTTPS."
    )
    assert vuln.info == expected_info
    assert vuln.severity == MEDIUM_LEVEL
    assert vuln.finding_class == HstsFinding


def test_sensitive_http_request_cookie_no_redirect(module):
    """
    Test a sensitive HTTP request (cookie) with no redirection.
    A MEDIUM level vulnerability is expected.
    """
    request, response = create_mock_objects(
        "http://test.com/",
        request_headers={"Cookie": "my_cookie=test"},
        response_headers={"Content-Type": "text/html"},
    )
    vuln = next(module.analyze(request, response), None)

    assert vuln is not None
    expected_info = (
        "Sensitive data (cookie in the request) was sent over an unencrypted HTTP connection to http://test.com/. "
        "The server did not enforce HTTPS."
    )
    assert vuln.info == expected_info
    assert vuln.severity == MEDIUM_LEVEL
    assert vuln.finding_class == HstsFinding


def test_sensitive_http_response_cookie_no_redirect(module):
    """
    Test a sensitive HTTP request (cookie in the response) with no redirection.
    A MEDIUM level vulnerability is expected.
    """
    request, response = create_mock_objects(
        "http://test.com/",
        response_headers={"Set-Cookie": "session_id=123", "Content-Type": "text/html"},
    )
    vuln = next(module.analyze(request, response), None)

    assert vuln is not None
    expected_info = (
        "Sensitive data (cookie in the response) was sent over an unencrypted HTTP connection to http://test.com/. "
        "The server did not enforce HTTPS."
    )
    assert vuln.info == expected_info
    assert vuln.severity == MEDIUM_LEVEL
    assert vuln.finding_class == HstsFinding


def test_sensitive_http_redirect_to_https(module):
    """
    Test a sensitive HTTP request (GET parameters) with redirection to HTTPS.
    A MEDIUM level vulnerability is expected.
    """
    request, response = create_mock_objects(
        "http://test.com/page?p=1",
        get_params=[["p", "1"]],
        response_status=301,
        redirection_url="https://test.com/page?p=1",
    )
    vuln = next(module.analyze(request, response), None)

    assert vuln is not None
    expected_info = (
        "Sensitive data (GET parameters) was sent over an unencrypted HTTP connection to http://test.com/page?p=1. "
        "The server redirected to an HTTPS URL, but the initial data and the redirection were exposed."
    )
    assert vuln.info == expected_info
    assert vuln.severity == MEDIUM_LEVEL
    assert vuln.finding_class == HstsFinding


def test_sensitive_http_redirect_to_http(module):
    """
    Test a sensitive HTTP request (GET parameters) with redirection to another HTTP URL.
    A LOW level vulnerability is expected.
    """
    request, response = create_mock_objects(
        "http://test.com/page?p=1",
        get_params=[["p", "1"]],
        response_status=302,
        redirection_url="http://test.com/new_page",
    )
    vuln = next(module.analyze(request, response), None)

    assert vuln is not None
    expected_info = (
        "Sensitive data (GET parameters) was sent over an unencrypted HTTP connection to http://test.com/page?p=1. "
        "The server redirected, but not to an HTTPS URL, leaving the initial data and the redirection exposed."
    )
    assert vuln.info == expected_info
    assert vuln.severity == LOW_LEVEL
    assert vuln.finding_class == HstsFinding


def test_deduplication_sensitive(module):
    """
    Test that sensitive vulnerabilities are reported only once per host/reason/type.
    """
    request1, response1 = create_mock_objects(
        "http://test.com/page1?p=1", get_params=[["p", "1"]]
    )
    request2, response2 = create_mock_objects(
        "http://test.com/page2?p=2", get_params=[["p", "2"]]
    )

    vuln1 = next(module.analyze(request1, response1), None)
    vuln2 = next(module.analyze(request2, response2), None)

    assert vuln1 is not None
    assert vuln2 is None


def test_deduplication_non_sensitive(module):
    """
    Test that non-sensitive information is reported only once per host.
    """
    request1, response1 = create_mock_objects(
        "http://test.com/page1", response_headers={"Content-Type": "text/html"}
    )
    request2, response2 = create_mock_objects(
        "http://test.com/page2", response_headers={"Content-Type": "text/html"}
    )

    vuln1 = next(module.analyze(request1, response1), None)
    vuln2 = next(module.analyze(request2, response2), None)

    assert vuln1 is not None
    assert vuln2 is None


def test_no_analysis_for_https(module):
    """
    Test that the module does nothing for HTTPS requests.
    """
    request, response = create_mock_objects("https://test.com/")
    vuln = next(module.analyze(request, response), None)

    assert vuln is None
