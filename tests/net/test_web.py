import httpx
import pytest

from wapitiCore.net.response import Response, detail_response
from wapitiCore.net.web import is_valid_url, shell_escape


def test_detail_response():
    response = Response(
        httpx.Response(
            200,
            headers=httpx.Headers([["foo", "bar"]]),
            content=b"body"
        ),
        url="http://perdu.com/"
    )

    detailed_response = detail_response(response)

    assert detailed_response["status_code"] == 200
    assert detailed_response["body"] == "body"
    assert ("foo", "bar") in detailed_response["headers"]  # Content-Length is present too


@pytest.mark.parametrize("url,expected", [
    # URLs valides
    ("http://example.com", True),
    ("https://example.com", True),
    ("http://sub.example.com:8080", True),
    ("https://localhost:3000", True),
    # URLs invalides
    ("ftp://example.com", False),
    ("http://", False),
    ("example.com", False),
    ("", False),
    ("http://example.com:777777777", False),
])
def test_is_valid_url(url, expected):
    """Test paramétré pour is_valid_url"""
    assert is_valid_url(url) == expected


def test_shell_escape_various_cases():
    """
    Tests the shell_escape function with various input cases.
    """
    assert shell_escape("hello world") == "hello world"
    assert shell_escape("") == ""
    assert shell_escape("123abcXYZ") == "123abcXYZ"
    assert shell_escape("test/path/file.txt") == "test/path/file.txt"

    assert shell_escape("\\") == "\\\\"
    assert shell_escape('"') == '\\"'
    assert shell_escape("$") == "\\$"
    assert shell_escape("!") == "\\!"
    assert shell_escape("`") == "\\`"

    assert shell_escape(r"C:\path") == r"C:\\path"
    assert shell_escape('He said "hello"') == 'He said \\"hello\\"'
    assert shell_escape("$HOME") == "\\$HOME"
    assert shell_escape("Hello!") == "Hello\\!"
    assert shell_escape("`command`") == "\\`command\\`"

    input_string_mixed = r'This is a "test" with \backslashes, $dollars, !exclamations, and `backticks`.'
    expected_string_mixed = r'This is a \"test\" with \\backslashes, \$dollars, \!exclamations, and \`backticks\`.'
    assert shell_escape(input_string_mixed) == expected_string_mixed

    assert shell_escape(r'\"$!') == r'\\\"\$\!'
    assert shell_escape('``!!$$') == r'\`\`\!\!\$\$'
    assert shell_escape('!!!!') == r'\!\!\!\!'
    assert shell_escape(r'!"$') == r'\!\"\$'
    assert shell_escape(r'`text`') == r'\`text\`'
