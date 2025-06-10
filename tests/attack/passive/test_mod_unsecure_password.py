import pytest
import httpx
from unittest.mock import MagicMock

from wapitiCore.attack.modules.passive.mod_unsecure_password import ModuleUnsecurePassword
from wapitiCore.definitions.cleartext_password_submission import CleartextPasswordSubmissionFinding
from wapitiCore.language.vulnerability import HIGH_LEVEL
from wapitiCore.net import Request, Response

# Patch log_red to avoid polluting test output
import wapitiCore.attack.modules.passive.mod_unsecure_password as mod_unsecure_password

mod_unsecure_password.log_red = MagicMock()

URL_HTTP = "http://example.com/form"
URL_HTTPS = "https://example.com/form"


def create_mock_objects(url: str, html_content: str):
    """Helper to create Request and Response objects with given HTML content."""
    req = Request(path=url, method="GET")
    req.set_headers(httpx.Headers({}))
    resp_obj = httpx.Response(status_code=200, content=html_content.encode("utf-8"))
    resp = Response(url=url, response=resp_obj)
    return req, resp


@pytest.fixture
def module():
    """Provide a fresh instance of the module for each test."""
    return ModuleUnsecurePassword()


@pytest.mark.parametrize(
    "url,html_content,expected_count",
    [
        # 1) HTTP form with password field -> should report 1 vulnerability
        (
            URL_HTTP,
            """<form action="/login" method="post">
                   <input type="password" name="pwd" />
                   <input type="submit" />
               </form>""",
            1,
        ),
        # 2) HTTPS form with password field -> no vulnerability
        (
            URL_HTTPS,
            """<form action="/login" method="post">
                   <input type="password" name="pwd" />
               </form>""",
            0,
        ),
        # 3) HTTP form without password field -> no vulnerability
        (
            URL_HTTP,
            """<form action="/search" method="get">
                   <input type="text" name="q" />
               </form>""",
            0,
        ),
    ],
)
def test_module_unsecure_password(module, url, html_content, expected_count):
    req, resp = create_mock_objects(url, html_content)
    vulns = list(module.analyze(req, resp))

    assert len(vulns) == expected_count
    if expected_count > 0:
        v = vulns[0]
        assert v.finding_class == CleartextPasswordSubmissionFinding
        assert v.severity == HIGH_LEVEL
        assert "Password field" in v.info


def test_module_unsecure_password_deduplication(module):
    """Same vulnerable form should only be reported once."""
    html = """<form action="/login" method="post">
                 <input type="password" name="pwd" />
              </form>"""

    req1, resp1 = create_mock_objects(URL_HTTP, html)
    req2, resp2 = create_mock_objects(URL_HTTP, html)

    vulns1 = list(module.analyze(req1, resp1))
    assert len(vulns1) == 1  # First time: reported

    vulns2 = list(module.analyze(req2, resp2))
    assert len(vulns2) == 0  # Second time: deduplicated


def test_module_unsecure_password_multiple_fields(module):
    """If a form has multiple password fields, each should be reported."""
    html = """<form action="/register" method="post">
                 <input type="password" name="pwd1" />
                 <input type="password" name="pwd2" />
              </form>"""

    req, resp = create_mock_objects(URL_HTTP, html)
    vulns = list(module.analyze(req, resp))

    assert len(vulns) == 2
    names = [v.parameter for v in vulns]
    assert {"pwd1", "pwd2"} == set(names)
