from tempfile import NamedTemporaryFile
import json
from unittest.mock import patch

import pytest
import respx
import httpx

from wapitiCore.main.getcookie import getcookie_main


@pytest.mark.asyncio
@respx.mock
async def test_getcookie_no_form():
    with NamedTemporaryFile("w") as json_fd:
        url = "https://www.amylandthesniffers.com/welcome/"
        respx.get(url).mock(
            return_value=httpx.Response(
                200,
                headers=[
                    ("set-cookie", "foo=bar; Path=/"),
                    ("set-cookie", "dead=beef; Path=/welcome/")
                ]
            )
        )

        await getcookie_main(["-u", "https://www.amylandthesniffers.com/welcome/", "-c", json_fd.name])

        data = json.load(open(json_fd.name))
        assert data == {
            '.www.amylandthesniffers.com': {
                '/': {
                    'foo': {
                        'expires': None,
                        'port': None,
                        'secure': False,
                        'value': 'bar',
                        'version': 0
                    }
                },
                '/welcome/': {
                    'dead': {
                        'expires': None,
                        'port': None,
                        'secure': False,
                        'value': 'beef',
                        'version': 0
                    }
                }
            }
        }


@pytest.mark.asyncio
@respx.mock
@patch("builtins.input", side_effect=["0", "bob", "letmein"])  # Mock calls to input()
async def test_getcookie_fill_one_form(_):
    with NamedTemporaryFile("w") as json_fd:
        url = "https://www.vboysstockholm.com/welcome/"
        respx.get(url).mock(
            return_value=httpx.Response(
                200,
                headers=[
                    ("set-cookie", "foo=bar; Path=/"),
                ],
                content=(
                    "<html><body>"
                    "<form method='POST' action='/login.php'>"
                    "<input type='text' name='username' />"
                    "<input type='password' name='passwd' />"
                    "</form>"
                )
            )
        )

        respx.post(
            "https://www.vboysstockholm.com/login.php",
            data={"username": "bob", "passwd": "letmein"}
        ).mock(
            return_value=httpx.Response(
                200,
                headers=[
                    ("set-cookie", "dead=beef; Path=/")
                ],
                content="Login is successful"
            )
        )

        await getcookie_main(["-u", "https://www.vboysstockholm.com/welcome/", "-c", json_fd.name])

        data = json.load(open(json_fd.name))
        assert data == {
            '.www.vboysstockholm.com': {
                '/': {
                    'foo': {
                        'expires': None,
                        'port': None,
                        'secure': False,
                        'value': 'bar',
                        'version': 0,
                    },
                    'dead': {
                        'expires': None,
                        'port': None,
                        'secure': False,
                        'value': 'beef',
                        'version': 0,
                    }
                }
            }
        }


@pytest.mark.asyncio
@respx.mock
async def test_getcookie_raw_credentials():
    with NamedTemporaryFile("w") as json_fd:
        url = "https://0xdf.gitlab.io/authenticate"
        respx.get(url).mock(return_value=httpx.Response(200))

        respx.post(
            url,
            json={"username": "ctf", "passwd": "good4u"},
            headers={"Content-Type": "application/json"},
        ).mock(
            return_value=httpx.Response(
                200,
                headers=[
                    ("set-cookie", "auth=true; Path=/")
                ],
                content="Login is successful"
            )
        )

        await getcookie_main(
            [
                "-u", "https://0xdf.gitlab.io/authenticate",
                "-c", json_fd.name,
                "--form-data", """{"username": "ctf", "passwd": "good4u"}""",
                "--form-enctype", "application/json"
            ]
        )

        data = json.load(open(json_fd.name))
        assert data == {
            '.0xdf.gitlab.io': {
                '/': {
                    'auth': {
                        'expires': None,
                        'port': None,
                        'secure': False,
                        'value': 'true',
                        'version': 0
                    }
                }
            }
        }


@pytest.mark.asyncio
@respx.mock
async def test_getcookie_basic_auth():
    with NamedTemporaryFile("w") as json_fd:
        url = "https://lundberg.github.io/respx/guide/"
        respx.get(url).mock(return_value=httpx.Response(200))

        await getcookie_main(["-u", url, "-c", json_fd.name, "--auth-user", "john", "--auth-password", "doe"])

        assert "Authorization" in respx.calls.last.request.headers
        assert respx.calls.last.request.headers["Authorization"] == "Basic am9objpkb2U="


@pytest.mark.asyncio
@respx.mock
@patch("builtins.input", side_effect=["0", "wapiti@wapiti.com", "P@ssw0rd!#$"])
async def test_getcookie_special_characters_in_credentials(_):
    """Test for issue #668: wapiti-getcookie should handle special characters like @ in username/password.

    This test verifies that usernames containing @ (like email addresses) and passwords with
    special characters are correctly handled by the interactive form filling mechanism.
    """
    with NamedTemporaryFile("w") as json_fd:
        url = "https://testapp.example.com/login"
        respx.get(url).mock(
            return_value=httpx.Response(
                200,
                headers=[
                    ("set-cookie", "session=initial; Path=/"),
                ],
                content=(
                    "<html><body>"
                    "<form method='POST' action='/authenticate'>"
                    "<input type='email' name='email' />"
                    "<input type='password' name='password' />"
                    "</form>"
                )
            )
        )

        # Verify the special characters are sent as-is (no escaping needed)
        respx.post(
            "https://testapp.example.com/authenticate",
            data={"email": "wapiti@wapiti.com", "password": "P@ssw0rd!#$"}
        ).mock(
            return_value=httpx.Response(
                200,
                headers=[
                    ("set-cookie", "auth_token=authenticated; Path=/")
                ],
                content="Login successful"
            )
        )

        await getcookie_main(["-u", url, "-c", json_fd.name])

        data = json.load(open(json_fd.name))
        # Verify cookies were saved correctly
        assert '.testapp.example.com' in data
        assert data['.testapp.example.com']['/']['auth_token']['value'] == 'authenticated'


@pytest.mark.asyncio
@respx.mock
async def test_getcookie_special_characters_raw_data():
    """Test special characters in raw form data for issue #668.

    Verify that JSON-encoded credentials with special characters work correctly
    when using --form-data parameter.
    """
    with NamedTemporaryFile("w") as json_fd:
        url = "https://api.example.com/login"
        respx.get(url).mock(return_value=httpx.Response(200))

        # Test with @ in username and special chars in password
        respx.post(
            url,
            json={"username": "test@example.com", "password": "p@ss&word=123"},
            headers={"Content-Type": "application/json"},
        ).mock(
            return_value=httpx.Response(
                200,
                headers=[
                    ("set-cookie", "token=valid; Path=/")
                ],
                content="Authentication successful"
            )
        )

        await getcookie_main(
            [
                "-u", url,
                "-c", json_fd.name,
                "--form-data", '{"username": "test@example.com", "password": "p@ss&word=123"}',
                "--form-enctype", "application/json"
            ]
        )

        data = json.load(open(json_fd.name))
        assert '.api.example.com' in data
        assert data['.api.example.com']['/']['token']['value'] == 'valid'


@pytest.mark.asyncio
@respx.mock
async def test_getcookie_special_characters_http_auth():
    """Test special characters in HTTP authentication for issue #668.

    Verify that usernames and passwords with special characters work correctly
    in HTTP Basic/Digest authentication.
    """
    with NamedTemporaryFile("w") as json_fd:
        url = "https://secure.example.com/protected"
        respx.get(url).mock(return_value=httpx.Response(200))

        # Test with @ in username (common for email-based auth)
        await getcookie_main([
            "-u", url,
            "-c", json_fd.name,
            "--auth-user", "admin@company.com",
            "--auth-password", "C0mpl3x!P@ss"
        ])

        # Verify Authorization header is correctly base64-encoded
        assert "Authorization" in respx.calls.last.request.headers
        # The header should contain base64-encoded "admin@company.com:C0mpl3x!P@ss"
        import base64
        expected_auth = base64.b64encode(b"admin@company.com:C0mpl3x!P@ss").decode()
        assert respx.calls.last.request.headers["Authorization"] == f"Basic {expected_auth}"
