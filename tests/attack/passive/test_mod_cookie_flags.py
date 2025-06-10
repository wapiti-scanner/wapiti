# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2025 Nicolas Surribas
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
import unittest
from typing import List, Tuple, Union
from unittest.mock import MagicMock

import httpx

from wapitiCore.net import Request, Response
from wapitiCore.definitions.secure_cookie import SecureCookieFinding
from wapitiCore.definitions.http_only import HttpOnlyFinding

from wapitiCore.attack.modules.passive.mod_cookie_flags import (
    ModuleCookieFlags,
    _get_cookies_from_response,
    INFO_COOKIE_HTTPONLY,
    INFO_COOKIE_SECURE,
)

log_red = MagicMock()


def create_mock_objects(
    headers: Union[dict, List[Tuple[str, str]]] = None,
    url: str = "http://example.com/login",
):
    """Helper to create independent Request and Response objects for each test."""
    if headers is None:
        headers = {}

    request = Request(path=url, method="GET")

    if (
        isinstance(headers, dict)
        and "Set-Cookie" in headers
        and isinstance(headers["Set-Cookie"], list)
    ):
        httpx_headers = []
        for cookie_str in headers["Set-Cookie"]:
            httpx_headers.append(("Set-Cookie", cookie_str))

        response = Response(
            url=url,
            response=httpx.Response(
                status_code=200, headers=httpx_headers, content=b""
            ),
        )
    else:
        response = Response(
            url=url,
            response=httpx.Response(status_code=200, content=b"", headers=headers),
        )
    return request, response


class TestModuleCookieFlags(unittest.TestCase):
    """
    Unit tests for the ModuleCookieFlags class and its helpers.
    """

    def test_get_cookies_from_response_no_cookies(self):
        """Tests that the function returns an empty list if no cookie is present."""
        _, response = create_mock_objects(headers={"Content-Type": "text/html"})
        cookies = _get_cookies_from_response(response)
        self.assertEqual(len(cookies), 0)

    def test_get_cookies_from_response_simple_cookie(self):
        """Tests that a simple cookie (without attributes) is correctly parsed."""
        _, response = create_mock_objects(headers={"Set-Cookie": ["session_id=abc123"]})
        cookies = _get_cookies_from_response(response)
        self.assertEqual(len(cookies), 1)
        name, domain, secure, httponly = cookies[0]
        self.assertEqual(name, "session_id")
        self.assertEqual(
            domain, "example.com"
        )  # Checks that the default domain is used
        self.assertFalse(secure)
        self.assertFalse(httponly)

    def test_get_cookies_from_response_full_cookie_header(self):
        """Tests a cookie header with all possible attributes."""
        _, response = create_mock_objects(
            headers={
                "Set-Cookie": ["session_id=abc123; Secure; HttpOnly; Domain=test.com"]
            }
        )
        cookies = _get_cookies_from_response(response)
        self.assertEqual(len(cookies), 1)
        name, domain, secure, httponly = cookies[0]
        self.assertEqual(name, "session_id")
        self.assertEqual(domain, "test.com")
        self.assertTrue(secure)
        self.assertTrue(httponly)

    def test_get_cookies_from_response_multiple_cookies(self):
        """Tests the parsing of multiple cookies in different headers."""
        # Now using a list of tuples as expected by httpx
        headers = [
            ("Set-Cookie", "id_user=123; HttpOnly"),
            ("Set-Cookie", "theme=dark; Secure"),
        ]
        _, response = create_mock_objects(headers=headers)
        cookies = _get_cookies_from_response(response)
        self.assertEqual(len(cookies), 2)
        # Checks the first cookie
        name1, _, secure1, httponly1 = cookies[0]
        self.assertEqual(name1, "id_user")
        self.assertFalse(secure1)
        self.assertTrue(httponly1)
        # Checks the second cookie
        name2, _, secure2, httponly2 = cookies[1]
        self.assertEqual(name2, "theme")
        self.assertTrue(secure2)
        self.assertFalse(httponly2)

    # === Tests for the analyze method ===

    def test_analyze_no_cookies_no_finding(self):
        """Tests that the method does not generate a finding if no cookie is present."""
        module = ModuleCookieFlags()
        request, response = create_mock_objects(headers={"Content-Type": "text/html"})
        findings = list(module.analyze(request, response))
        self.assertEqual(len(findings), 0)

    def test_analyze_cookie_missing_both_flags(self):
        """Tests a cookie without both the HttpOnly and Secure flags."""
        module = ModuleCookieFlags()
        request, response = create_mock_objects(
            headers={"Set-Cookie": ["session_id=abc123"]}
        )
        findings = list(module.analyze(request, response))
        self.assertEqual(len(findings), 2)
        # Checks the HttpOnly finding
        self.assertTrue(findings[0].finding_class, HttpOnlyFinding)
        self.assertEqual(
            findings[0].info,
            INFO_COOKIE_HTTPONLY.format("session_id", "http://example.com/login"),
        )
        # Checks the Secure finding
        self.assertTrue(findings[1].finding_class, SecureCookieFinding)
        self.assertEqual(
            findings[1].info,
            INFO_COOKIE_SECURE.format("session_id", "http://example.com/login"),
        )

    def test_analyze_cookie_missing_httponly_flag(self):
        """Tests a cookie that is only missing the HttpOnly flag."""
        module = ModuleCookieFlags()
        request, response = create_mock_objects(
            headers={"Set-Cookie": ["session_id=abc123; Secure"]}
        )
        findings = list(module.analyze(request, response))
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0].finding_class, HttpOnlyFinding)
        self.assertEqual(
            findings[0].info,
            INFO_COOKIE_HTTPONLY.format("session_id", "http://example.com/login"),
        )

    def test_analyze_cookie_missing_secure_flag(self):
        """Tests a cookie that is only missing the Secure flag."""
        module = ModuleCookieFlags()
        request, response = create_mock_objects(
            headers={"Set-Cookie": ["session_id=abc123; HttpOnly"]}
        )
        findings = list(module.analyze(request, response))
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0].finding_class, SecureCookieFinding)
        self.assertEqual(
            findings[0].info,
            INFO_COOKIE_SECURE.format("session_id", "http://example.com/login"),
        )

    def test_analyze_cookie_with_all_flags(self):
        """Tests a cookie with both flags."""
        module = ModuleCookieFlags()
        request, response = create_mock_objects(
            headers={"Set-Cookie": ["session_id=abc123; Secure; HttpOnly"]}
        )
        findings = list(module.analyze(request, response))
        self.assertEqual(len(findings), 0)

    def test_analyze_de_duplication_logic(self):
        """
        Tests that the same problem on the same cookie is reported only once.
        """
        module = ModuleCookieFlags()
        request, response = create_mock_objects(
            headers={"Set-Cookie": ["session_id=abc123"]}
        )

        # First analysis of an insecure cookie
        findings_run1 = list(module.analyze(request, response))
        self.assertEqual(len(findings_run1), 2)

        # Second analysis of the same response with the same module
        # The state of the module object is preserved
        findings_run2 = list(module.analyze(request, response))
        self.assertEqual(len(findings_run2), 0)

        # We test that a new cookie with a different name is properly reported
        request, response = create_mock_objects(
            headers={"Set-Cookie": ["another_cookie=def456"]}
        )
        findings_run3 = list(module.analyze(request, response))
        self.assertEqual(len(findings_run3), 2)

    def test_analyze_malformed_cookie(self):
        """Tests a malformed cookie."""
        module = ModuleCookieFlags()
        request, response = create_mock_objects(
            headers={"Set-Cookie": ["trololol; Secure; HttpOnly"]}
        )
        findings = list(module.analyze(request, response))
        self.assertEqual(len(findings), 0)

    def test_analyze_cookie_without_value(self):
        """Tests an empty cookie."""
        module = ModuleCookieFlags()
        request, response = create_mock_objects(headers={"Set-Cookie": [""]})
        findings = list(module.analyze(request, response))
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
