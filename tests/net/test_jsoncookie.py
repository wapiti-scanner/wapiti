from typing import Dict
from http.cookiejar import CookieJar
from unittest import mock
from unittest.mock import MagicMock, mock_open
import pytest
import respx
from httpx import Cookies
from wapitiCore.net.jsoncookie import JsonCookie

json_cookie_path = "./cookie.txt"

cookie_content = """
{
    ".testphp.vulnweb.com": {
        "/": {
        "login": {
            "value": "test%2Ftest",
            "expires": null,
            "secure": false,
            "port": null,
            "version": 0
        }
        }
    }
}
"""

cookie_content_result = """
{
    "127.0.0.1": {
        "/": {
        "secret_cookie": {
            "value": "secret,
            "expires": null,
            "secure": false,
            "port": null,
            "version": 0
        }
        }
    }
}
"""

cookie_domain_1 = ".testphp.vulnweb.com"
cookie_domain_2 = "127.0.0.1"


def get_mock_open(files: Dict[str, str]):
    def open_mock(filename, *args, **kwargs):
        for expected_filename, content in files.items():
            if filename == expected_filename:
                return mock_open(read_data=content).return_value
        raise FileNotFoundError('(mock) Unable to open {filename}')
    return MagicMock(side_effect=open_mock)

@pytest.mark.asyncio
@respx.mock
async def test_jsoncookie():

    files = {
        f'{json_cookie_path}': cookie_content,
    }

    json_cookie = JsonCookie()

    with mock.patch("builtins.open", get_mock_open(files)) as open_mock:
        try:
            json_cookie.load(json_cookie_path)
            open_mock.assert_called_once_with(json_cookie_path, "r+", encoding='utf-8')
        except (IOError, ValueError):
            pytest.fail("Unexpected IOError ..")

    assert json_cookie.filename == json_cookie_path
    assert len(json_cookie.cookiedict) == 1

    cookie_jar: CookieJar = json_cookie.cookiejar(cookie_domain_1)

    assert cookie_jar is not None
    assert cookie_jar.__len__() == 1

    cookies = Cookies()
    cookies.set("secret_cookie", "secret", cookie_domain_1, "/")
    cookies.set("secret_cookie", "secret", cookie_domain_2, "/")

    assert json_cookie.addcookies(cookies) is not False

    cookie_jar = json_cookie.cookiejar(cookie_domain_1)

    assert cookie_jar is not None
    assert cookie_jar.__len__() == 2

    assert json_cookie.delete(cookie_domain_1) is True

    cookie_jar = json_cookie.cookiejar(cookie_domain_1)

    assert cookie_jar is not None
    assert cookie_jar.__len__() == 0

    cookie_jar = json_cookie.cookiejar(cookie_domain_2)

    assert cookie_jar is not None
    assert cookie_jar.__len__() == 1

    with mock.patch("builtins.open", get_mock_open(files)) as open_mock:
        try:
            json_cookie.dump()
            open_mock.assert_called_once_with(json_cookie_path, "r+", encoding='utf-8')
        except (IOError, ValueError):
            pytest.fail("Unexpected IOError ..")

@pytest.mark.asyncio
async def test_exception_jsoncookie():
    json_cookie = JsonCookie()

    with mock.patch("builtins.open", MagicMock(side_effect=IOError)) as open_mock:
        try:
            json_cookie.load(json_cookie_path)
            pytest.fail("Should raise an exception ..")
        except (IOError, ValueError):
            open_mock.assert_called_with(json_cookie_path, "w+", encoding='utf-8')
