import json
import time
from unittest.mock import MagicMock
from typing import Generator, Any
from urllib.parse import quote

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


STACK_TRACE = "Fatal error: Uncaught Exception in /var/www/html/index.php:12"
DISCLOSED = "Response contains potential system path: /var/www/html/index.php"
SERVICES = "C:\\Windows\\System32\\drivers\\etc\\services"
XXE = (
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///usr/etc/networks">]>'
    "<foo>&xxe;</foo>"
)


def infos(module, request: Request, content: str, content_type: str = "text/html"):
    request, response = create_mock_objects(content, content_type=content_type, request=request)
    return [vuln.info for vuln in get_all_vulnerabilities(module, request, response)]


def get_request(**params) -> Request:
    return Request(
        "http://test.com/p.php?" + "&".join(f"{name}={quote(value, safe='')}" for name, value in params.items())
    )


def json_request(document) -> Request:
    return Request("http://test.com/api", method="POST", enctype="application/json", post_params=json.dumps(document))


@pytest.mark.parametrize(
    "request_, content",
    [
        (get_request(id="1'", debug_state="trace:/var/www/html/index.php:ok"), STACK_TRACE),
        (
            get_request(id="1'", note="see /var/www/html/index.php"),
            f'<input type="hidden" name="note" value="see /var/www/html/index.php">{STACK_TRACE}',
        ),
        (json_request({"id": "1'", "cfg": {"note": "see /var/www/html/index.php"}}), STACK_TRACE),
        (
            Request(
                "http://test.com/soap", method="POST", enctype="text/xml",
                post_params="<req><id>1'</id><note>see /var/www/html/index.php</note></req>",
            ),
            STACK_TRACE,
        ),
    ],
    ids=["unrelated parameter", "unrelated parameter also echoed", "unrelated json field", "unrelated xml field"],
)
def test_path_inside_an_unrelated_sent_value_is_reported(module, request_, content):
    """A sent value containing the path does not make every occurrence of that path an echo."""
    assert infos(module, request_, content) == [DISCLOSED]


def test_parent_directory_of_a_sent_path_is_reported(module):
    request = get_request(id="1'", tpl="/var/www/html/index.php")
    assert infos(module, request, "DocumentRoot is /var/www/html here") == [
        "Response contains potential system path: /var/www/html"
    ]


@pytest.mark.parametrize(
    "request_, content",
    [
        (
            get_request(file="../../../../../../../../../../etc/passwd"),
            "open /var/www/app/static/../../../../../../../../../../etc/passwd: no such file",
        ),
        (
            Request("http://test.com/x", method="POST", enctype="text/xml", post_params=XXE),
            "FileNotFoundException: /usr/etc/networks at /opt/tomcat/webapps/app/WEB-INF/x.jsp",
        ),
    ],
    ids=["traversal printed with the real base directory", "xxe error with a real server path"],
)
def test_server_path_next_to_a_payload_is_reported(module, request_, content):
    assert any(
        "/var/www/app/static/" in info or "/opt/tomcat/" in info for info in infos(module, request_, content)
    )


@pytest.mark.parametrize(
    "rendering",
    ["&#039;", "&#x27;", "&#39;", "&apos;"],
    ids=["php-htmlspecialchars", "python-html.escape", "aspnet-HtmlEncode", "html5-apos"],
)
def test_html_escaped_reflection_is_not_reported(module, rendering):
    request = get_request(file="x'<b>/etc/passwd</b>\"")
    assert not infos(module, request, f"No result for x{rendering}&lt;b&gt;/etc/passwd&lt;/b&gt;&quot;")


@pytest.mark.parametrize(
    "request_, content, content_type",
    [
        (
            json_request({"user": "joe", "options": [{"file": "/etc/passwd"}]}),
            json.dumps({"error": "cannot open", "file": "/etc/passwd"}),
            "application/json",
        ),
        (
            get_request(q='say "/etc/passwd"'),
            json.dumps({"query": 'say "/etc/passwd"'}),
            "application/json",
        ),
        (
            Request(
                "http://test.com/soap", method="POST", enctype="text/xml",
                post_params="<req><file>/etc/passwd</file><user>joe</user></req>",
            ),
            "File /etc/passwd not found",
            "text/html",
        ),
        (
            Request("http://test.com/up.php", file_params=[["f", ("/etc/passwd", b"x", "text/plain")]]),
            "Upload of /etc/passwd refused",
            "text/html",
        ),
        (
            # Query string injection: ?/etc/passwd is parsed as a valueless parameter name
            Request("http://test.com/p.php?" + quote("/etc/passwd")),
            "No result for <b>/etc/passwd</b>",
            "text/html",
        ),
        (
            Request("http://test.com/p.php", method="POST", post_params=[["file", SERVICES]]),
            f"Cannot read {SERVICES}.",
            "text/html",
        ),
    ],
    ids=["json leaf", "json escaped", "xml field", "uploaded file name", "query string injection", "windows path"],
)
def test_echoed_value_is_not_reported(module, request_, content, content_type):
    assert not infos(module, request_, content, content_type)


@pytest.mark.parametrize(
    "payload, content",
    [
        ("/etc/passwd\0", "No result for <b>/etc/passwd\0</b>"),
        ("/etc/passwd\0", "No result for <b>/etc/passwd</b>"),
        ("/etc/passwd\0.php", "include(/etc/passwd): failed to open stream"),
        ("/etc/passwd\0.php", "include(/etc/passwd.php): failed to open stream"),
    ],
    ids=["nul kept", "nul dropped", "cut at nul", "nul stripped"],
)
def test_nul_byte_payload_reflection_is_not_reported(module, payload, content):
    request = Request("http://test.com/p.php", method="POST", post_params=[["file", payload]])
    assert not infos(module, request, content)


@pytest.mark.parametrize(
    "request_, content",
    [
        (get_request(file="../" * 10 + "etc/passwd"), "Error: open /etc/passwd: permission denied"),
        (get_request(file="....//" * 20 + "etc/passwd"), "java.io.FileNotFoundException: /etc/passwd (Permission denied)"),
        (get_request(file="page.php/" + "../" * 10 + "etc/passwd"), "Forbidden path /etc/passwd"),
        (get_request(file="../" * 10 + "etc/passwd\0"), "Forbidden path /etc/passwd"),
        (get_request(file="file:///etc/passwd"), "java.io.FileNotFoundException: /etc/passwd (Permission denied)"),
        (get_request(file="file://" + SERVICES), f"Could not find file '{SERVICES}'."),
        (get_request(file=SERVICES + "::$DATA"), f"Could not find file '{SERVICES}'."),
        (get_request(xml=XXE), "java.io.FileNotFoundException: /usr/etc/networks (No such file or directory)"),
        (
            Request("http://test.com/x", method="POST", enctype="text/xml", post_params=XXE),
            "java.io.FileNotFoundException: /usr/etc/networks (No such file or directory)",
        ),
    ],
    ids=[
        "relative traversal", "traversal filter bypass", "traversal after a value", "traversal with nul",
        "file url", "windows file url", "ntfs stream suffix", "xxe entity in a parameter", "xxe entity in the body",
    ],
)
def test_target_resolved_from_a_payload_is_not_reported(module, request_, content):
    """The server often prints the path a payload resolves to (mod_file, mod_xxe), not the payload."""
    assert not infos(module, request_, content)


@pytest.mark.parametrize(
    "content",
    [
        f"Warning: include({SERVICES}): Failed to open stream in /var/www/html/index.php",
        f"Cannot open &quot;{SERVICES}&quot;",
        f"Tried {SERVICES}, then gave up",
    ],
    ids=["php include", "html quoted", "followed by a comma"],
)
def test_windows_payload_followed_by_punctuation_is_not_reported(module, content):
    request = Request("http://test.com/p.php", method="POST", post_params=[["file", SERVICES]])
    assert not any(SERVICES in info for info in infos(module, request, content))


@pytest.mark.parametrize(
    "value, content",
    [
        ("a';cat /etc/passwd;'", "No result for a\\';cat /etc/passwd;\\'"),
        ("';cat /etc/passwd", '<a href="?q=\';cat+/etc/passwd">next</a>'),
        (" /etc/passwd ", "No result for '/etc/passwd'"),
    ],
    ids=["addslashes", "plus for spaces", "trimmed"],
)
def test_transformed_echo_is_not_reported(module, value, content):
    assert not infos(module, get_request(q=value), content)


@pytest.mark.parametrize(
    "value, content",
    [
        ("../" * 10 + "Windows/System32/drivers/etc/services", f"Access to the path '{SERVICES}' is denied."),
        ("C:/Windows/System32/drivers/etc/services", f"Could not find file '{SERVICES}'."),
        ("file:///C:/Windows/System32/drivers/etc/services", f"Could not find file '{SERVICES}'."),
    ],
    ids=["traversal", "forward slashes", "file url with forward slashes"],
)
def test_windows_target_resolved_from_a_payload_is_not_reported(module, value, content):
    assert not infos(module, get_request(file=value), content)


def test_xxe_entity_in_an_uploaded_file_is_not_reported(module):
    request = Request(
        "http://test.com/upload.php", file_params=[["doc", ("content.xml", XXE.encode(), "text/xml")]]
    )
    assert not infos(module, request, "java.io.FileNotFoundException: /usr/etc/networks (No such file or directory)")


def test_long_echoed_value_full_of_paths_stays_fast(module):
    """The copies of each sent value are searched once per response, not once per path found."""
    value = "include /etc/nginx/conf.d/app.conf;\n" * 4000
    request = Request("http://test.com/settings.php", method="POST", post_params=[["config", value]])
    started = time.perf_counter()
    assert not infos(module, request, f"<textarea>{value.strip()}</textarea>")
    assert time.perf_counter() - started < 5


def test_sent_value_equal_to_the_path_hides_every_occurrence(module):
    """Known limitation: when the value IS the path, a copy of it can't be told apart from a disclosure."""
    assert not infos(module, get_request(id="1'", tpl="/var/www/html/index.php"), STACK_TRACE)
