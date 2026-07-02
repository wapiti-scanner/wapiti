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
    assert len(cookie_jar) == 1

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
    assert len(cookie_jar) == 2

    assert json_cookie.delete(cookie_domain_1) is True

    cookie_jar = json_cookie.cookiejar(cookie_domain_1)

    assert cookie_jar is not None
    assert len(cookie_jar) == 0

    cookie_jar = json_cookie.cookiejar(cookie_domain_2)

    assert cookie_jar is not None
    assert len(cookie_jar) == 1

    with mock.patch("builtins.open", get_mock_open(files)) as open_mock:
        try:
            json_cookie.dump()
            open_mock.assert_called_once_with(json_cookie_path, "r+", encoding='utf-8')
        except (IOError, ValueError):
            pytest.fail("Unexpected IOError ..")


@pytest.mark.asyncio
async def test_jsoncookie_dotless_local_hostname():
    """A cookie saved (e.g. via wapiti-getcookie) for a dotless local hostname such as
    "localhost" must be found back when reading it during the actual scan, using the
    same domain the crawler would pass (the raw hostname, with no leading dot)."""
    empty_cookie_path = "./empty_cookie.txt"
    files = {
        f'{empty_cookie_path}': "{}",
    }

    json_cookie = JsonCookie()
    with mock.patch("builtins.open", get_mock_open(files)):
        json_cookie.load(empty_cookie_path)

    cookie = Cookie(
        version=0,
        name="SESSIONID",
        value="df298788980e4793220097b8896b1a98",
        port=None,
        port_specified=False,
        domain="localhost",
        domain_specified=True,
        domain_initial_dot=False,
        path="/",
        path_specified=True,
        secure=True,
        expires=None,
        discard=True,
        comment=None,
        comment_url=None,
        rest={'HttpOnly': None},
        rfc2109=False
    )
    cookie_jar = CookieJar()
    cookie_jar.set_cookie(cookie)

    assert json_cookie.addcookies(cookie_jar) is not False
    # addcookies() must apply the same ".local" normalization used for reading,
    # otherwise the cookie is stored under a key cookiejar() will never look up.
    assert ".localhost.local" in json_cookie.cookiedict

    result_jar = json_cookie.cookiejar("localhost")
    assert len(result_jar) == 1
    assert list(result_jar)[0].value == "df298788980e4793220097b8896b1a98"


@pytest.mark.asyncio
async def test_exception_jsoncookie():
    json_cookie = JsonCookie()

    with mock.patch("builtins.open", MagicMock(side_effect=IOError)) as open_mock:
        try:
            json_cookie.load(json_cookie_path)
            pytest.fail("Should raise an exception ..")
        except (IOError, ValueError):
            open_mock.assert_called_with(json_cookie_path, "w+", encoding='utf-8')
