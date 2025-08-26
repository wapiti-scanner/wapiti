import pytest
import httpx
from unittest.mock import MagicMock

from wapitiCore.net import Request, Response
from wapitiCore.attack.modules.passive.mod_http_headers import (
    ModuleHttpHeaders,
    HSTS_NOT_SET,
    XCONTENT_TYPE_NOT_SET,
    XFRAME_OPTIONS_NOT_SET,
    INVALID_HSTS,
    INVALID_XCONTENT_TYPE,
    INVALID_XFRAME_OPTIONS,
)
from wapitiCore.definitions.http_headers import (
    ClickjackingFinding,
    MimeTypeConfusionFinding,
    HstsFinding,
)
from wapitiCore.language.vulnerability import LOW_LEVEL

from wapitiCore.attack.modules.passive import mod_http_headers


URL_HTTP = "http://example.com"
URL_HTTPS = "https://example.com"


@pytest.fixture(autouse=True)
def patch_logs(monkeypatch):
    monkeypatch.setattr(mod_http_headers, "log_red", MagicMock())
    monkeypatch.setattr(mod_http_headers, "log_orange", MagicMock())


@pytest.fixture
def module():
    return ModuleHttpHeaders()


def create_mock_objects(url: str, headers: dict | None = None):
    if headers is None:
        headers = {}

    req = Request(path=url, method="GET")
    req.set_headers(httpx.Headers({}))
    resp_obj = httpx.Response(
        status_code=200, headers=headers, content=b"<html></html>"
    )
    resp = Response(url=url, response=resp_obj)
    return req, resp


@pytest.mark.parametrize(
    "url,headers,expected_infos,expected_classes",
    [
        # 1) All headers missing on HTTPS -> 3 findings (XFO, XCTO, HSTS)
        (
            URL_HTTPS,
            {},
            [XFRAME_OPTIONS_NOT_SET, XCONTENT_TYPE_NOT_SET, HSTS_NOT_SET],
            [ClickjackingFinding, MimeTypeConfusionFinding, HstsFinding],
        ),
        # 2) Invalid X-Frame-Options, other headers are valid -> 1 finding
        (
            URL_HTTP,
            {"X-Frame-Options": "ALLOWALL", "X-Content-Type-Options": "nosniff"},
            [INVALID_XFRAME_OPTIONS],
            [ClickjackingFinding],
        ),
        # 3) Invalid X-Content-Type-Options, other headers are valid -> 1 finding
        (
            URL_HTTP,
            {"X-Content-Type-Options": "invalid", "X-Frame-Options": "DENY"},
            [INVALID_XCONTENT_TYPE],
            [MimeTypeConfusionFinding],
        ),
        # 4) Invalid HSTS on HTTPS, other headers are valid -> 1 finding
        (
            URL_HTTPS,
            {
                "Strict-Transport-Security": "no-max-age",
                "X-Frame-Options": "DENY",
                "X-Content-Type-Options": "nosniff",
            },
            [INVALID_HSTS],
            [HstsFinding],
        ),
    ],
)
def test_module_http_headers_findings(
    module, url, headers, expected_infos, expected_classes
):
    """Test different scenarios where one or more headers are missing or invalid."""
    req, resp = create_mock_objects(url, headers)
    vulns = list(module.analyze(req, resp))

    # Check that infos and finding classes match expectations exactly
    assert [v.info for v in vulns] == expected_infos
    assert [v.finding_class for v in vulns] == expected_classes
    assert all(v.severity == LOW_LEVEL for v in vulns)


def test_module_http_headers_all_ok(module):
    """If all headers are present and valid, no findings should be reported."""
    headers = {
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Strict-Transport-Security": "max-age=63072000",
    }
    req, resp = create_mock_objects(URL_HTTPS, headers)
    assert list(module.analyze(req, resp)) == []


def test_module_http_headers_hsts_ignored_on_http(module):
    """HSTS must be ignored when scheme is HTTP, even if invalid."""
    headers = {
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Strict-Transport-Security": "no-max-age",  # Invalid, but should be ignored on HTTP
    }
    req, resp = create_mock_objects(URL_HTTP, headers)
    assert list(module.analyze(req, resp)) == []


def test_module_http_headers_deduplication(module):
    """Repeated issues on the same netloc should be reported only once."""
    # First pass: 3 findings because all headers are missing
    req1, resp1 = create_mock_objects(URL_HTTPS, {})
    vulns1 = list(module.analyze(req1, resp1))
    assert len(vulns1) == 3

    # Second pass: same issues, same netloc -> no new findings
    req2, resp2 = create_mock_objects(URL_HTTPS, {})
    vulns2 = list(module.analyze(req2, resp2))
    assert vulns2 == []
