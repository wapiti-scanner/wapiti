import json
from typing import List, Tuple, Union
from unittest.mock import MagicMock

import pytest
import httpx

from wapitiCore.attack.modules.passive.mod_https_redirect import ModuleHttpsRedirect
from wapitiCore.net import Request
from wapitiCore.net.response import Response
from wapitiCore.language.vulnerability import LOW_LEVEL, MEDIUM_LEVEL
from wapitiCore.definitions.https_redirect import HstsFinding

# pylint: disable=redefined-outer-name


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
        headers=request_headers,
    )

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


# ---------------------------------------------------------------------------
# Non-sensitive HTML ordering regressions: a safe redirect to HTTPS is not a
# finding, so it must neither consume the host's occurrence nor be counted as
# a suppressed alert.
# ---------------------------------------------------------------------------

def safe_redirect(url="http://test.com/index.html", target="https://test.com/index.html"):
    """Non-sensitive HTML 3xx response redirecting to HTTPS: never a finding."""
    return create_mock_objects(
        url,
        response_status=301,
        redirection_url=target,
        response_headers={"Content-Type": "text/html"},
    )


def insecure_html(url="http://test.com/page"):
    """Non-sensitive HTML 200 served in clear text: the finding under test."""
    return create_mock_objects(url, response_headers={"Content-Type": "text/html"})


def test_safe_redirect_does_not_consume_the_host_occurrence(module):
    """safe -> unsafe -> repeated unsafe: only the repeat is suppressed."""
    request, response = safe_redirect()
    assert next(module.analyze(request, response), None) is None
    assert module.suppressed_findings == 0

    request, response = insecure_html()
    vuln = next(module.analyze(request, response), None)
    assert vuln is not None
    assert vuln.severity == LOW_LEVEL
    assert vuln.request is request

    request, response = insecure_html("http://test.com/other")
    assert next(module.analyze(request, response), None) is None
    assert module.suppressed_findings == 1
    assert dict(module.suppressed_by_category) == {HstsFinding.name(): 1}


def test_repeated_safe_redirects_record_nothing(module):
    """Repeated safe redirects leave no occurrence and no suppression behind."""
    for _ in range(3):
        request, response = safe_redirect()
        assert next(module.analyze(request, response), None) is None

    state = module.get_state()
    assert state["occurrences"] == []
    assert state["suppressed_findings"] == 0
    assert state["suppressed_by_category"] == {}

    # The host slot is still free for the real finding.
    request, response = insecure_html()
    assert next(module.analyze(request, response), None) is not None


def test_unsafe_then_safe_adds_no_false_suppression(module):
    """A safe redirect after the real alert must not be counted as suppressed."""
    request, response = insecure_html()
    assert next(module.analyze(request, response), None) is not None

    request, response = safe_redirect()
    assert next(module.analyze(request, response), None) is None

    assert module.suppressed_findings == 0
    assert module.get_state()["occurrences"] == [["test.com", 1]]


def test_json_state_roundtrip_keeps_safe_and_unsafe_semantics(module):
    """Persisted state must not turn a safe redirect into a consumed occurrence."""
    request, response = insecure_html()
    assert next(module.analyze(request, response), None) is not None
    request, response = safe_redirect()
    assert next(module.analyze(request, response), None) is None

    restored = ModuleHttpsRedirect()
    restored.load_state(json.loads(json.dumps(module.get_state())))

    request, response = insecure_html("http://test.com/other")
    assert next(restored.analyze(request, response), None) is None
    assert restored.suppressed_findings == 1

    # State built from safe redirects only stays empty across a JSON roundtrip.
    safe_only = ModuleHttpsRedirect()
    for _ in range(2):
        request, response = safe_redirect("http://other.com/")
        assert next(safe_only.analyze(request, response), None) is None

    empty_state = json.loads(json.dumps(safe_only.get_state()))
    assert empty_state["occurrences"] == []
    assert empty_state["suppressed_findings"] == 0

    restored_empty = ModuleHttpsRedirect()
    restored_empty.load_state(empty_state)
    request, response = safe_redirect("http://other.com/")
    assert next(restored_empty.analyze(request, response), None) is None
    assert restored_empty.suppressed_findings == 0
    request, response = insecure_html("http://other.com/x")
    assert next(restored_empty.analyze(request, response), None) is not None


def test_non_html_non_sensitive_response_is_ignored(module):
    """Unchanged invariant: non-HTML bodies are out of scope and consume nothing."""
    request, response = create_mock_objects(
        "http://test.com/api", response_headers={"Content-Type": "application/json"}
    )
    assert next(module.analyze(request, response), None) is None
    assert module.get_state()["occurrences"] == []
    assert module.suppressed_findings == 0


def test_sensitive_keys_and_cap_are_unchanged(module):
    """Unchanged invariant: sensitive keys stay distinct per reason, cap stays 1."""
    get_request, get_response = create_mock_objects(
        "http://test.com/page?p=1", get_params=[["p", "1"]]
    )
    post_request, post_response = create_mock_objects(
        "http://test.com/submit", method="POST", post_params=[["p", "1"]]
    )

    assert next(module.analyze(get_request, get_response), None) is not None
    assert next(module.analyze(post_request, post_response), None) is not None
    assert next(module.analyze(get_request, get_response), None) is None

    assert module.suppressed_findings == 1
    assert sorted(entry[0][1] for entry in module.get_state()["occurrences"]) == [
        "GET parameters",
        "POST data",
    ]
