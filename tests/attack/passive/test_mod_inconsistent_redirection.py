import httpx
import pytest

from wapitiCore.attack.modules.passive.mod_inconsistent_redirection import ModuleInconsistentRedirection
from wapitiCore.net import Request, Response


@pytest.mark.parametrize(
    "status, content_type, body, expected_count",
    [
        # Case 1: Not a redirect
        (200, "text/html", b"<a href='/'>link</a>", 0),
        # Case 2: Redirect but not HTML
        (302, "application/json", b'{"ok": true}', 0),
        # Case 3: Redirect + HTML but empty body
        (302, "text/html", b"", 0),
        # Case 4: Redirect + HTML without links/forms
        (302, "text/html", b"<html><p>Hello</p></html>", 0),
        # Case 5: Redirect + HTML with link
        (302, "text/html", b"<html><a href='/'>Click</a></html>", 1),
        # Case 6: Redirect + HTML with form
        (302, "text/html", b"<html><form action='/login'></form></html>", 1),
    ]
)
def test_inconsistent_redirection_cases(status, content_type, body, expected_count):
    module = ModuleInconsistentRedirection()
    request = Request("http://example.com")
    response = Response(
        response=httpx.Response(
            status_code=status,
            headers={"Content-Type": content_type, "Location": "http://example.org"},
            content=body,
        ),
        url="http://example.com"
    )

    vulns = list(module.analyze(request, response))
    assert len(vulns) == expected_count


def test_inconsistent_redirection_deduplication():
    """Ensure same response md5 does not produce duplicate findings."""
    module = ModuleInconsistentRedirection()
    request = Request("http://example.com")

    body = b"<html><a href='/'>Click</a></html>"
    response = Response(
        response=httpx.Response(
            status_code=302,
            headers={"Content-Type": "text/html", "Location": "http://example.org"},
            content=body,
        ),
        url="http://example.com"
    )

    # First analysis → should yield a vuln
    vulns_first = list(module.analyze(request, response))
    assert len(vulns_first) == 1

    # Second analysis with same content (same md5) → should yield nothing
    vulns_second = list(module.analyze(request, response))
    assert len(vulns_second) == 0
