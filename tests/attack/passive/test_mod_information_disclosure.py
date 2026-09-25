from unittest.mock import MagicMock
from typing import Generator, Any

import pytest

from wapitiCore.attack.modules.passive.mod_information_disclosure import (
    ModuleInformationDisclosure,
)
from wapitiCore.definitions.information_disclosure import InformationDisclosureFinding
from wapitiCore.language.vulnerability import LOW_LEVEL
from wapitiCore.model.vulnerability import VulnerabilityInstance
from wapitiCore.net import Request, Response

# pylint: disable=redefined-outer-name


def create_mock_objects(content: str, content_type: str = "text/html", request: Request = None):
    """Helper to create a Request and a mock Response object."""
    request = request or Request("http://test.com/")
    response = MagicMock(spec=Response)
    response.content = content
    response.type = content_type
    return request, response


@pytest.fixture
def module():
    """Fixture to provide a fresh instance of the module."""
    return ModuleInformationDisclosure()


def get_all_vulnerabilities(
    module: ModuleInformationDisclosure, request: Request, response: Response
) -> Generator[VulnerabilityInstance, Any, None]:
    """Helper to get all vulnerabilities from the generator."""
    yield from module.analyze(request, response)


@pytest.mark.parametrize(
    "content, expected_info",
    [
        (
            "An error occurred in /var/www/html/index.php",
            "Response contains potential system path: /var/www/html/index.php",
        ),
        (
            "Path not found: /home/user/app/file.py",
            "Response contains potential system path: /home/user/app/file.py",
        ),
        (
            "An error occurred at C:\\Program Files\\App\\error.log",
            "Response contains potential system path: C:\\Program Files\\App\\error.log",
        ),
        (
            "A file was not found at C:\\Users\\Admin\\Desktop\\config.json",
            "Response contains potential system path: C:\\Users\\Admin\\Desktop\\config.json",
        ),
        (
            "Path disclosure: /home/test/file.sh and C:\\Windows\\System32\\config.sys",
            "Response contains potential system path: /home/test/file.sh",
        ),
        (
            "Path disclosure: /home/test/file.sh and C:\\Windows\\System32\\config.sys",
            "Response contains potential system path: C:\\Windows\\System32\\config.sys",
        ),
        (
            # We will report the path but truncated because "Custom App" contains a whitespace
            "An error occurred at C:\\Program Files\\Custom App\\error.log",
            "Response contains potential system path: C:\\Program Files\\Custom",
        ),
    ],
)
def test_path_disclosure_detected(module, content, expected_info):
    """Test that vulnerabilities are detected for various path patterns."""
    request, response = create_mock_objects(content)
    vulns = list(get_all_vulnerabilities(module, request, response))

    assert len(vulns) >= 1
    found_vuln = any(vuln.info == expected_info for vuln in vulns)
    assert found_vuln, f"Expected vulnerability not found: {expected_info}"
    assert all(vuln.severity == LOW_LEVEL for vuln in vulns)
    assert all(vuln.finding_class == InformationDisclosureFinding for vuln in vulns)


def test_no_path_disclosure(module):
    """Test that no vulnerability is reported when no path is present."""
    content = "Everything is working as expected."
    request, response = create_mock_objects(content)
    vulns = list(get_all_vulnerabilities(module, request, response))
    assert len(vulns) == 0


def test_base64_blob_is_not_reported_as_path(module):
    """A long base64 token (e.g. ASP.NET __VIEWSTATE) that happens to contain a
    '/var/'-like chunk must not be reported as a system path."""
    blob = (
        "/9bff8dyxROWIg1Q5FY3kO0652nWbIMB9GmY7D07y3W5YP70OQDBnleJ8Q9yyTqUtCtIPeT"
        "4AfhEUw9mjxssNwcC5nUJVaNwPKwfTS9qR0iO0VZZxmjYJ/var/ZxKzLojXRU2ET2LqU3Wq"
        "HvHt2kbkoTdtu6z8l6BaWDHeVjtApfTtBBgzev3GFSQ3t9VNucw2p0nGTH/cRD9vdzLC857"
    )
    content = f'<input type="hidden" name="__VIEWSTATE" value="{blob}" />'
    request, response = create_mock_objects(content)
    vulns = list(get_all_vulnerabilities(module, request, response))
    assert len(vulns) == 0


def test_short_base64_with_keyword_segment_is_not_reported(module):
    """A short base64 chunk (< length cap) with a keyword segment is still
    rejected thanks to the base64-looking components."""
    content = (
        '{"token":"/aB3xK9mQ2wZ7pL5nR8vT1cY4dF6gHkS/var/Zx9Kq2Mw7Pl5Nr8Vt1Cy4Df6jU/config"}'
    )
    request, response = create_mock_objects(content, content_type="application/json")
    vulns = list(get_all_vulnerabilities(module, request, response))
    assert len(vulns) == 0


def test_hex_and_uuid_path_components_still_reported(module):
    """A genuine path with a hex-hash or UUID directory (lower-case + digits,
    no upper-case) must still be reported."""
    content = "cache miss at /opt/app/f47ac10b-58cc-4372-a567-0e02b2c3d479/data.log"
    request, response = create_mock_objects(content)
    vulns = list(get_all_vulnerabilities(module, request, response))
    assert len(vulns) == 1
    assert "f47ac10b-58cc-4372-a567-0e02b2c3d479" in vulns[0].info


def test_no_path_disclosure_unsupported_content_type(module):
    """Test that no vulnerability is reported for unsupported content types."""
    content = "An error occurred in /var/www/html/index.php"
    request, response = create_mock_objects(content, content_type="image/jpeg")
    vulns = list(get_all_vulnerabilities(module, request, response))
    assert len(vulns) == 0


def test_path_deduplication(module):
    """Test that the same path is reported only once, even if it appears multiple times."""
    content = (
        "Error at /var/www/html/index.php. Another error at /var/www/html/index.php"
    )
    request, response = create_mock_objects(content)
    vulns = list(get_all_vulnerabilities(module, request, response))
    assert len(vulns) == 1
    assert (
        vulns[0].info
        == "Response contains potential system path: /var/www/html/index.php."
    )


@pytest.mark.parametrize(
    "request_",
    [
        Request("http://test.com/search.php?q=%2Fetc%2Fpasswd"),
        Request("http://test.com/search.php", method="POST", post_params=[["q", "/../../../etc/passwd"]]),
        Request(
            "http://test.com/api", method="POST", enctype="application/json",
            post_params='{"q": "/etc/passwd"}',
        ),
    ],
    ids=["query string", "form body", "raw body"],
)
def test_path_sent_by_the_client_is_not_reported(module, request_):
    """A path echoed back from the request (e.g. a mod_file payload reflected by a search page)
    is not disclosed by the server."""
    content = 'No result for <b>/etc/passwd</b><input value="/etc/passwd">'
    request, response = create_mock_objects(content, request=request_)
    assert not list(get_all_vulnerabilities(module, request, response))


def test_disclosed_path_next_to_a_reflected_payload_is_reported(module):
    """Only the reflected payload is ignored: a real path leaked by the error is still reported."""
    content = (
        "Warning: include(/etc/passwd): failed to open stream in "
        "/var/www/html/page.php on line 3"
    )
    request, response = create_mock_objects(
        content, request=Request("http://test.com/page.php?file=%2Fetc%2Fpasswd")
    )
    vulns = list(get_all_vulnerabilities(module, request, response))
    assert [vuln.info for vuln in vulns] == ["Response contains potential system path: /var/www/html/page.php"]
