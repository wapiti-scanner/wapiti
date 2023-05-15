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
