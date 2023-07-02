from http.cookiejar import CookieJar, Cookie
from unittest import mock
from unittest.mock import MagicMock
import pytest
import respx

from tests import get_mock_open
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

    new_cookie_jar = CookieJar()
    for domain in (cookie_domain_1, cookie_domain_2):
        cookie = Cookie(
            version=0,
            name="secret_cookie",
            value="secret",
            port=None,
            port_specified=False,
            domain=domain,
            domain_specified=True,
            domain_initial_dot=False,
            path="/",
            path_specified=True,
            secure=False,
            expires=None,
            discard=True,
            comment=None,
            comment_url=None,
            rest={'HttpOnly': None},
            rfc2109=False
        )
        new_cookie_jar.set_cookie(cookie)

    assert json_cookie.addcookies(new_cookie_jar) is not False

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
