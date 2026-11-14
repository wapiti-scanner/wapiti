from unittest.mock import MagicMock

import pytest
import httpx

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

# pylint: disable=redefined-outer-name

URL_HTTP = "http://example.com"
URL_HTTPS = "https://example.com"

VALID_X_HEADERS = {"X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff"}


def hsts_headers(value: str) -> dict:
    return {**VALID_X_HEADERS, "Strict-Transport-Security": value}


@pytest.fixture(autouse=True)
def patch_logs(monkeypatch):
    monkeypatch.setattr(mod_http_headers, "log_red", MagicMock())
    monkeypatch.setattr(mod_http_headers, "log_orange", MagicMock())


@pytest.fixture
def module():
    return ModuleHttpHeaders()


def create_mock_objects(url: str, headers: dict | list[tuple[str, str]] | None = None):
    if headers is None:
        headers = {}

    req = Request(path=url, method="GET")
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
    assert not list(module.analyze(req, resp))


def test_module_http_headers_hsts_ignored_on_http(module):
    """HSTS must be ignored when scheme is HTTP, even if invalid."""
    headers = {
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Strict-Transport-Security": "no-max-age",  # Invalid, but should be ignored on HTTP
    }
    req, resp = create_mock_objects(URL_HTTP, headers)
    assert not list(module.analyze(req, resp))


def test_module_http_headers_deduplication(module):
    """Repeated issues on the same netloc should be reported only once."""
    # First pass: 3 findings because all headers are missing
    req1, resp1 = create_mock_objects(URL_HTTPS, {})
    vulns1 = list(module.analyze(req1, resp1))
    assert len(vulns1) == 3

    # Second pass: same issues, same netloc -> no new findings
    req2, resp2 = create_mock_objects(URL_HTTPS, {})
    vulns2 = list(module.analyze(req2, resp2))
    assert not vulns2


def test_module_http_headers_same_invalid_value_deduplicated(module):
    """Same header carrying the same invalid value on the same host -> reported once."""
    req1, resp1 = create_mock_objects(
        URL_HTTP, {"X-Frame-Options": "ALLOWALL", "X-Content-Type-Options": "nosniff"}
    )
    req2, resp2 = create_mock_objects(
        URL_HTTP, {"X-Frame-Options": "ALLOWALL", "X-Content-Type-Options": "nosniff"}
    )
    assert [v.info for v in module.analyze(req1, resp1)] == [INVALID_XFRAME_OPTIONS]
    assert not list(module.analyze(req2, resp2))  # identical posture -> deduplicated


def test_module_http_headers_distinct_invalid_values_reported(module):
    """Same header with two DIFFERENT invalid values on the same host -> both surface."""
    req1, resp1 = create_mock_objects(
        URL_HTTP, {"X-Frame-Options": "ALLOWALL", "X-Content-Type-Options": "nosniff"}
    )
    req2, resp2 = create_mock_objects(
        URL_HTTP, {"X-Frame-Options": "SOMETHING-ELSE", "X-Content-Type-Options": "nosniff"}
    )
    assert [v.info for v in module.analyze(req1, resp1)] == [INVALID_XFRAME_OPTIONS]
    # Different offending value -> distinct posture -> reported again.
    assert [v.info for v in module.analyze(req2, resp2)] == [INVALID_XFRAME_OPTIONS]


@pytest.mark.parametrize(
    "hsts_value",
    [
        # Plain, case-insensitive directive name, whitespace around '='.
        "max-age=31536000",
        "MAX-AGE=31536000",
        "max-age = 31536000",
        # RFC 6797 examples use a quoted-string; quoted-pair escapes are legal.
        'max-age="31536000"',
        'max-age="\\31536000"',
        # Leading zeroes still denote a positive lifetime.
        "max-age=00031536000",
        # Empty elements produced by trailing semicolons are allowed by the grammar.
        "max-age=31536000;",
        "max-age=31536000;;",
        # Unknown extension directives are ignored, not treated as max-age.
        "max-age=31536000; includeSubDomains; preload",
        "max-age=31536000; includeSubDomains",
        "max-age=31536000; extension=token",
        'max-age=31536000; extension="a;b\\"c"',
        'max-age=31536000; report-uri="https://example.test/a;max-age=0"',
        # No int() conversion: a huge (but syntactically valid) delta-seconds value.
        pytest.param("max-age=" + "9" * 5000, id="huge_digits_without_int_conversion"),
    ],
)
def test_hsts_effective_policy_accepted(module, hsts_value):
    """A single positive ASCII max-age directive must not produce a finding."""
    req, resp = create_mock_objects(URL_HTTPS, hsts_headers(hsts_value))
    assert not list(module.analyze(req, resp))


@pytest.mark.parametrize(
    "hsts_value",
    [
        # Zero disables the policy (RFC 6797 section 6.1.1 NOTE and section 8.1).
        "max-age=0",
        "max-age=000",
        'max-age="0"',
        # delta-seconds = 1*DIGIT: no sign, no letters, no empty value.
        "max-age=-1",
        "max-age=+1",
        "max-age=abc",
        "max-age=",
        'max-age=""',
        "max-age",
        "includeSubDomains",
        # Exactly one max-age directive is required.
        "max-age=1; max-age=0",
        "max-age=0; max-age=31536000",
        # Substring lookalikes are not a directive value.
        "max-age=31536000x",
        "max-age=31536000, max-age=0",
    ],
)
def test_hsts_ineffective_policy_rejected(module, hsts_value):
    """Missing, duplicate or non-positive max-age must be reported as invalid."""
    req, resp = create_mock_objects(URL_HTTPS, hsts_headers(hsts_value))
    vulns = list(module.analyze(req, resp))
    assert [v.info for v in vulns] == [INVALID_HSTS]
    assert [v.finding_class for v in vulns] == [HstsFinding]
    assert all(v.severity == LOW_LEVEL for v in vulns)


@pytest.mark.parametrize(
    "hsts_value",
    [
        "max-age=10; includeSubDomains=1",
        "max-age=10; includeSubDomains; includeSubDomains",
        "max-age=10; bad directive=x",
        "max-age=10; extension=a,b",
        "max-age=10; extension=a; extension=b",
        "x-max-age=31536000",
        'max-age=10; extension="unterminated',
        'max-age=10; extension="bad\x01"',
        'max-age=10; extension="bad\nline"',
    ],
)
def test_hsts_invalid_adjunct_directives_rejected(module, hsts_value):
    """A structurally invalid companion directive makes the whole STS field ignored."""
    req, resp = create_mock_objects(URL_HTTPS, hsts_headers(hsts_value))
    assert [v.info for v in module.analyze(req, resp)] == [INVALID_HSTS]


def test_hsts_missing_reports_not_set(module):
    """A missing STS header keeps the existing 'not set' finding."""
    req, resp = create_mock_objects(URL_HTTPS, VALID_X_HEADERS)
    vulns = list(module.analyze(req, resp))
    assert [v.info for v in vulns] == [HSTS_NOT_SET]
    assert [v.finding_class for v in vulns] == [HstsFinding]


@pytest.mark.parametrize(
    "values,expected",
    [
        (["no-max-age", "max-age=31536000"], [INVALID_HSTS]),
        (["max-age=0", "max-age=31536000"], [INVALID_HSTS]),
        (["max-age=31536000", "no-max-age"], []),
        (["max-age=31536000", "max-age=0"], []),
    ],
)
def test_hsts_only_first_physical_header_is_processed(module, values, expected):
    """RFC 6797 section 8.1: later STS fields must not rescue or override the first."""
    headers = list(VALID_X_HEADERS.items())
    headers += [("Strict-Transport-Security", value) for value in values]
    req, resp = create_mock_objects(URL_HTTPS, headers)
    assert [v.info for v in module.analyze(req, resp)] == expected


def test_hsts_repeated_invalid_posture_deduplicated(module):
    """The same ineffective value on the same host is still reported only once."""
    headers = hsts_headers("max-age=0")
    req1, resp1 = create_mock_objects(URL_HTTPS, headers)
    req2, resp2 = create_mock_objects(URL_HTTPS, headers)
    assert [v.info for v in module.analyze(req1, resp1)] == [INVALID_HSTS]
    assert not list(module.analyze(req2, resp2))


def test_hsts_distinct_invalid_postures_reported(module):
    """Different ineffective values remain distinct postures for deduplication."""
    req1, resp1 = create_mock_objects(URL_HTTPS, hsts_headers("max-age=0"))
    req2, resp2 = create_mock_objects(URL_HTTPS, hsts_headers("max-age=-1"))
    assert [v.info for v in module.analyze(req1, resp1)] == [INVALID_HSTS]
    assert [v.info for v in module.analyze(req2, resp2)] == [INVALID_HSTS]


def test_hsts_valid_then_invalid_is_not_suppressed(module):
    """A valid positive policy must not consume the invalid-posture dedup slot."""
    req1, resp1 = create_mock_objects(URL_HTTPS, hsts_headers("max-age=31536000"))
    assert not list(module.analyze(req1, resp1))
    req2, resp2 = create_mock_objects(URL_HTTPS, hsts_headers("max-age=0"))
    assert [v.info for v in module.analyze(req2, resp2)] == [INVALID_HSTS]


def test_hsts_zero_ignored_on_http(module):
    """HSTS remains HTTPS-only; max-age=0 on plain HTTP must not produce a finding."""
    req, resp = create_mock_objects(URL_HTTP, hsts_headers("max-age=0"))
    assert not list(module.analyze(req, resp))


def test_hsts_zero_warning_is_meaningful(module):
    """The warning must not claim max-age is absent when the policy is merely zero."""
    req, resp = create_mock_objects(URL_HTTPS, hsts_headers("max-age=0"))
    vulns = list(module.analyze(req, resp))
    assert [v.info for v in vulns] == [INVALID_HSTS]
    assert "not found" not in vulns[0].info
    assert "max-age" in vulns[0].info
