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


def test_standard_object_moved_body_is_not_reported():
    """The framework 'Object moved to <a href="target">here</a>' body whose
    only link is the redirection target itself must not be flagged."""
    module = ModuleInconsistentRedirection()
    url = "https://example.com/PressReleasePage.aspx?PRID=2280153"
    location = "/PressReleasePage.aspx?PRID=2280153&reg=48&lang=2"
    body = (
        b'<html><head><title>Object moved</title></head><body>\n'
        b'<h2>Object moved to <a href="/PressReleasePage.aspx?PRID=2280153&amp;reg=48&amp;lang=2">here</a>.</h2>\n'
        b'</body></html>'
    )
    response = Response(
        response=httpx.Response(
            status_code=302,
            headers={"Content-Type": "text/html; charset=utf-8", "Location": location},
            content=body,
        ),
        url=url,
    )
    assert len(list(module.analyze(Request(url), response))) == 0


def test_directory_redirection_boilerplate_is_not_reported():
    """A directory redirection (the Location only appends a trailing slash) whose
    'Object Moved' boilerplate links to the target must not be flagged, even when
    the body link uses a different scheme (http) than the Location header (https).
    Real-world case: https://example.com/blogs -> https://example.com/blogs/
    """
    module = ModuleInconsistentRedirection()
    url = "https://example.com/blogs"
    location = "https://example.com/blogs/"
    body = (
        b"<head><title>Document Moved</title></head>\n"
        b'<body><h1>Object Moved</h1>This document may be found '
        b'<a HREF="http://example.com/blogs/">here</a></body>'
    )
    response = Response(
        response=httpx.Response(
            status_code=301,
            headers={"Content-Type": "text/html; charset=UTF-8", "Location": location},
            content=body,
        ),
        url=url,
    )
    assert len(list(module.analyze(Request(url), response))) == 0


def test_redirect_body_with_extra_link_is_reported():
    """A redirect body linking somewhere *other* than the target is the real
    leak and must be reported."""
    module = ModuleInconsistentRedirection()
    url = "https://example.com/go"
    location = "/target"
    body = (
        b'<html><body><a href="/target">here</a>'
        b'<a href="/secret/panel">panel</a></body></html>'
    )
    response = Response(
        response=httpx.Response(
            status_code=302,
            headers={"Content-Type": "text/html", "Location": location},
            content=body,
        ),
        url=url,
    )
    assert len(list(module.analyze(Request(url), response))) == 1


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
