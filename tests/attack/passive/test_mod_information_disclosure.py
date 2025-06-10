import pytest
from unittest.mock import MagicMock
from typing import Generator, Any

from wapitiCore.attack.modules.passive.mod_information_disclosure import (
    ModuleInformationDisclosure,
)
from wapitiCore.definitions.information_disclosure import InformationDisclosureFinding
from wapitiCore.language.vulnerability import LOW_LEVEL
from wapitiCore.model.vulnerability import VulnerabilityInstance
from wapitiCore.net import Request, Response


def create_mock_objects(content: str, content_type: str = "text/html"):
    """Helper to create mock Request and Response objects."""
    request = MagicMock(spec=Request)
    request.url = "http://test.com/"
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
