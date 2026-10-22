import json
from unittest.mock import AsyncMock, patch
from http.cookiejar import CookieJar

import pytest
import httpx
import respx

from wapitiCore.net.auth import (
    async_try_form_login,
    authenticate_with_side_file,
    login_with_raw_data,
    load_form_script,
    check_http_auth
)
from wapitiCore.net.classes import CrawlerConfiguration, FormCredential, RawCredential
from wapitiCore.net import Request
from wapitiCore.net.scope import Scope

# Sample HTML for a login page
LOGIN_PAGE_HTML = """
<html>
  <body>
    <form action="/login" method="post">
      <input type="text" name="username">
      <input type="password" name="password">
      <input type="submit" value="Login">
    </form>
  </body>
</html>
"""

# Sample HTML for a page after successful login
LOGGED_IN_HTML = """
<html>
  <body>
    <h1>Welcome!</h1>
    <a href="/logout">Logout</a>
  </body>
</html>
"""

# Sample HTML for a page after failed login
LOGIN_FAILED_HTML = """
<html>
  <body>
    <p>Invalid credentials</p>
    <form action="/login" method="post">
      <input type="text" name="username">
      <input type="password" name="password">
      <input type="submit" value="Login">
    </form>
  </body>
</html>
"""


@pytest.mark.asyncio
class TestAuth:
    """Unit tests for the auth module."""

    @pytest.fixture
    def crawler_configuration(self):
        """Returns a default CrawlerConfiguration."""
        base_request = Request("http://wapiti.test/")
        return CrawlerConfiguration(base_request)

    @respx.mock
    async def test_form_login_success_no_headless(self, crawler_configuration):
        """Test successful form-based login without headless mode."""
        login_url = "http://wapiti.test/login"
        form_creds = FormCredential(
            url=login_url,
            username="admin",
            password="password"
        )

        respx.get(login_url).mock(return_value=httpx.Response(200, text=LOGIN_PAGE_HTML))
        respx.post("http://wapiti.test/login").mock(
            return_value=httpx.Response(200, text=LOGGED_IN_HTML, headers={"Set-Cookie": "sessionid=123"})
        )

        is_logged_in, form, disconnect_urls = await async_try_form_login(
            crawler_configuration,
            form_creds,
            headless_mode="no"
        )

        assert is_logged_in is True
        assert form == {'login_field': 'username', 'password_field': 'password'}
        assert any("/logout" in url for url in disconnect_urls)
        assert any(c.name == "sessionid" for c in crawler_configuration.cookies)

    @respx.mock
    async def test_form_login_failure_no_headless(self, crawler_configuration):
        """Test failed form-based login without headless mode."""
        login_url = "http://wapiti.test/login"
        form_creds = FormCredential(
            url=login_url,
            username="admin",
            password="wrongpassword"
        )

        respx.get(login_url).mock(return_value=httpx.Response(200, text=LOGIN_PAGE_HTML))
        respx.post("http://wapiti.test/login").mock(return_value=httpx.Response(200, text=LOGIN_FAILED_HTML))

        is_logged_in, form, disconnect_urls = await async_try_form_login(
            crawler_configuration,
            form_creds,
            headless_mode="no"
        )

        assert is_logged_in is False
        assert form == {'login_field': 'username', 'password_field': 'password'}
        assert not disconnect_urls

    @respx.mock
    @patch("wapitiCore.net.auth.async_playwright")
    async def test_form_login_success_headless(self, mock_async_playwright, crawler_configuration):
        """Test successful form-based login with headless mode."""
        login_url = "http://wapiti.test/login"
        form_creds = FormCredential(
            url=login_url,
            username="admin",
            password="password"
        )

        mock_page = AsyncMock()
        mock_page.content.return_value = LOGIN_PAGE_HTML
        mock_page.url = login_url
        mock_context = AsyncMock()
        mock_context.new_page.return_value = mock_page
        mock_context.cookies.return_value = []
        mock_browser = AsyncMock()
        mock_browser.new_context.return_value = mock_context
        mock_playwright = AsyncMock()
        mock_playwright.firefox.launch.return_value = mock_browser
        mock_async_playwright.return_value.__aenter__.return_value = mock_playwright

        respx.post("http://wapiti.test/login").mock(
            return_value=httpx.Response(200, text=LOGGED_IN_HTML, headers={"Set-Cookie": "sessionid=123"})
        )

        is_logged_in, form, disconnect_urls = await async_try_form_login(
            crawler_configuration,
            form_creds,
            headless_mode="hidden"
        )

        assert is_logged_in is True
        assert form == {'login_field': 'username', 'password_field': 'password'}
        assert any("/logout" in url for url in disconnect_urls)
        assert any(c.name == "sessionid" for c in crawler_configuration.cookies)

    @respx.mock
    async def test_login_with_raw_data(self, crawler_configuration):
        """Test login with raw data."""
        login_url = "http://wapiti.test/api/login"
        raw_creds = RawCredential(
            url=login_url,
            data='{"user": "admin", "pass": "secret"}',
            enctype="application/json"
        )

        respx.post(login_url).mock(
            return_value=httpx.Response(200, json={"status": "ok"}, headers={"Set-Cookie": "token=abc"})
        )

        await login_with_raw_data(crawler_configuration, raw_creds)

        assert any(c.name == "token" for c in crawler_configuration.cookies)
        sent_request = respx.calls.last.request
        assert sent_request.method == "POST"
        assert sent_request.content == b'{"user": "admin", "pass": "secret"}'
        assert sent_request.headers["content-type"] == "application/json"

    @patch("wapitiCore.net.auth.async_playwright")
    async def test_authenticate_with_side_file(self, mock_async_playwright, tmp_path, crawler_configuration):
        """Test authentication using a .side file."""
        side_content = {
            "url": "http://wapiti.test",
            "tests": [{
                "commands": [
                    {"command": "open", "target": "/login"},
                    {"command": "type", "target": "id=username", "value": "admin"},
                    {"command": "type", "target": "css=input[name=password]", "value": "password"},
                    {"command": "click", "target": "xpath=//input[@type='submit']"}
                ]
            }]
        }
        side_file = tmp_path / "login.side"
        side_file.write_text(json.dumps(side_content))

        mock_page = AsyncMock()
        mock_context = AsyncMock()
        mock_context.new_page.return_value = mock_page
        mock_context.cookies.return_value = [
            {
                "name": "sessionid",
                "value": "from-side-file",
                "domain": "wapiti.test",
                "path": "/",
                "secure": False,
                "httpOnly": False
            }
        ]
        mock_browser = AsyncMock()
        mock_browser.new_context.return_value = mock_context
        mock_playwright = AsyncMock()
        mock_playwright.firefox.launch.return_value = mock_browser
        mock_async_playwright.return_value.__aenter__.return_value = mock_playwright

        cookies = await authenticate_with_side_file(crawler_configuration, str(side_file), "hidden")

        assert any(c.name == "sessionid" for c in cookies)
        # We can't easily access a cookie by name from a CookieJar, so we iterate
        for cookie in cookies:
            if cookie.name == "sessionid":
                assert cookie.value == "from-side-file"
                break
        else:
            pytest.fail("Cookie not found")

        mock_page.goto.assert_called_once_with("http://wapiti.test/login")
        mock_page.fill.assert_any_call("#username", "admin")
        mock_page.fill.assert_any_call("input[name=password]", "password")
        mock_page.click.assert_called_once_with("//input[@type='submit']")

    async def test_load_form_script(self, tmp_path, crawler_configuration):
        """Test loading an external authentication script."""
        script_content = """
import asyncio

async def run(crawler_configuration, form_credential, headless):
    # This is a dummy script that just sets a cookie
    from http.cookiejar import Cookie
    from time import time
    cookie = Cookie(
        version=0, name='auth_script_cookie', value='success',
        port=None, port_specified=False,
        domain='wapiti.test', domain_specified=True, domain_initial_dot=False,
        path='/', path_specified=True,
        secure=False, expires=int(time()) + 3600,
        discard=True, comment=None, comment_url=None, rest={}
    )
    crawler_configuration.cookies.set_cookie(cookie)
"""
        script_file = tmp_path / "auth_script.py"
        script_file.write_text(script_content)

        crawler_configuration.cookies = CookieJar()
        await load_form_script(str(script_file), crawler_configuration)

        assert any(c.name == "auth_script_cookie" for c in crawler_configuration.cookies)
        for cookie in crawler_configuration.cookies:
            if cookie.name == "auth_script_cookie":
                assert cookie.value == "success"
                break
        else:
            pytest.fail("Cookie not found")

    @respx.mock
    async def test_async_login_raw_credentials_urlencoded(self, crawler_configuration):
        target_url = "http://perdu.com/userinfo.php"
        raw_credential = RawCredential(
            "uname=besthacker&pass=letmein",
            target_url
        )
        respx.post(target_url, data={"uname": "besthacker", "pass": "letmein"}).mock(
            return_value=httpx.Response(
                200,
                text="<p>Success</p>",
                headers={"Set-Cookie": "login=besthacker;"}
            )
        )

        await login_with_raw_data(crawler_configuration, raw_credential)
        assert any(c.name == "login" and c.value == "besthacker" for c in crawler_configuration.cookies)

    @respx.mock
    async def test_check_http_auth_success(self, crawler_configuration):
        respx.get(crawler_configuration.base_request.url).mock(return_value=httpx.Response(200))
        assert await check_http_auth(crawler_configuration) is True

    @respx.mock
    async def test_check_http_auth_failure(self, crawler_configuration):
        respx.get(crawler_configuration.base_request.url).mock(return_value=httpx.Response(401))
        assert await check_http_auth(crawler_configuration) is False


def login_page_posting_to(action: str) -> str:
    return f"""
<html><body>
  <form action="{action}" method="post">
    <input type="text" name="username">
    <input type="password" name="password">
  </form>
</body></html>
"""


@pytest.mark.asyncio
@respx.mock
async def test_form_login_refuses_foreign_host():
    """A login form (injected or not) pointing to another host must not receive the credentials."""
    crawler_configuration = CrawlerConfiguration(Request("http://wapiti.test/"))
    form_creds = FormCredential(url="http://wapiti.test/login", username="admin", password="password")
    respx.get("http://wapiti.test/login").mock(
        return_value=httpx.Response(200, text=login_page_posting_to("http://evil.test/steal"))
    )
    steal_route = respx.post("http://evil.test/steal").mock(return_value=httpx.Response(200, text=LOGGED_IN_HTML))

    result = await async_try_form_login(
        crawler_configuration, form_creds, scope=Scope(Request("http://wapiti.test/"), "folder")
    )

    assert result == (False, {}, [])
    assert not steal_route.called


@pytest.mark.asyncio
@respx.mock
async def test_form_login_refuses_base_tag_to_foreign_host():
    """<base href> is another way for the page to move a relative action to a foreign host."""
    crawler_configuration = CrawlerConfiguration(Request("http://wapiti.test/"))
    form_creds = FormCredential(url="http://wapiti.test/login", username="admin", password="password")
    respx.get("http://wapiti.test/login").mock(
        return_value=httpx.Response(
            200,
            text='<html><head><base href="http://evil.test/x/"></head><body>' + login_page_posting_to("login")
        )
    )
    steal_route = respx.post("http://evil.test/x/login").mock(return_value=httpx.Response(200, text=LOGGED_IN_HTML))

    result = await async_try_form_login(crawler_configuration, form_creds)

    assert result == (False, {}, [])
    assert not steal_route.called


@pytest.mark.asyncio
@respx.mock
async def test_form_login_external_page_posting_into_scope():
    """An external login page whose form submits to the scanned target is allowed through the scan scope."""
    crawler_configuration = CrawlerConfiguration(Request("http://wapiti.test/"))
    form_creds = FormCredential(url="http://sso.test/login", username="admin", password="password")
    respx.get("http://sso.test/login").mock(
        return_value=httpx.Response(200, text=login_page_posting_to("http://wapiti.test/auth"))
    )
    auth_route = respx.post("http://wapiti.test/auth").mock(return_value=httpx.Response(200, text=LOGGED_IN_HTML))

    is_logged_in, form, _ = await async_try_form_login(
        crawler_configuration, form_creds, scope=Scope(Request("http://wapiti.test/"), "folder")
    )

    assert is_logged_in is True
    assert form == {"login_field": "username", "password_field": "password"}
    assert auth_route.called


@pytest.mark.asyncio
@respx.mock
async def test_form_login_same_registrable_domain_is_allowed():
    """www.example.com posting to accounts.example.com is a common legitimate setup."""
    crawler_configuration = CrawlerConfiguration(Request("http://www.example.com/"))
    form_creds = FormCredential(url="http://www.example.com/login", username="admin", password="password")
    respx.get("http://www.example.com/login").mock(
        return_value=httpx.Response(200, text=login_page_posting_to("http://accounts.example.com/login"))
    )
    auth_route = respx.post("http://accounts.example.com/login").mock(
        return_value=httpx.Response(200, text=LOGGED_IN_HTML)
    )

    is_logged_in, _, _ = await async_try_form_login(crawler_configuration, form_creds)

    assert is_logged_in is True
    assert auth_route.called


@pytest.mark.asyncio
@respx.mock
async def test_form_login_follows_redirect_to_identity_provider():
    """The login page may redirect to an IdP: the form is then checked against the final page, not --form-url."""
    crawler_configuration = CrawlerConfiguration(Request("http://wapiti.test/"))
    form_creds = FormCredential(url="http://wapiti.test/login", username="admin", password="password")
    respx.get("http://wapiti.test/login").mock(
        return_value=httpx.Response(302, headers={"Location": "http://idp.test/realms/app/login"})
    )
    respx.get("http://idp.test/realms/app/login").mock(
        return_value=httpx.Response(200, text=login_page_posting_to("/realms/app/authenticate"))
    )
    idp_route = respx.post("http://idp.test/realms/app/authenticate").mock(
        return_value=httpx.Response(200, text=LOGGED_IN_HTML)
    )
    wrong_route = respx.post("http://wapiti.test/realms/app/authenticate").mock(return_value=httpx.Response(404))

    with patch("wapitiCore.net.auth.log_orange") as mock_log_orange:
        is_logged_in, _, _ = await async_try_form_login(crawler_configuration, form_creds)

    assert is_logged_in is True
    assert idp_route.called
    assert not wrong_route.called
    # The operator is told where the credentials went, with a properly formatted message
    message, *args = mock_log_orange.call_args.args
    assert "http://idp.test/realms/app/login" in message.format(*args)


@pytest.mark.asyncio
@respx.mock
async def test_form_login_refuses_other_port_on_same_ip():
    """Without a registrable domain, only the exact host:port of the login page (or the scope) is trusted."""
    crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:9011/"))
    form_creds = FormCredential(url="http://127.0.0.1:9011/login", username="admin", password="password")
    respx.get("http://127.0.0.1:9011/login").mock(
        return_value=httpx.Response(200, text=login_page_posting_to("http://127.0.0.1:9015/steal"))
    )
    steal_route = respx.post("http://127.0.0.1:9015/steal").mock(return_value=httpx.Response(200, text=LOGGED_IN_HTML))

    result = await async_try_form_login(
        crawler_configuration, form_creds, scope=Scope(Request("http://127.0.0.1:9011/"), "folder")
    )

    assert result == (False, {}, [])
    assert not steal_route.called


def test_is_login_destination_allowed_rules():
    from wapitiCore.net.auth import is_login_destination_allowed

    page = "https://www.example.com/login"
    assert is_login_destination_allowed("https://www.example.com/auth", page)
    assert is_login_destination_allowed("https://www.example.com:8443/auth", page)  # same registrable domain
    assert is_login_destination_allowed("https://accounts.example.com/auth", page)
    assert is_login_destination_allowed("http://www.example.com/auth", page)  # downgrade is warned, not refused
    assert not is_login_destination_allowed("https://example.net/auth", page)
    assert not is_login_destination_allowed("https://evil.example.net/auth", page)
    assert not is_login_destination_allowed("/auth", page)

    page = "http://127.0.0.1:9011/login"
    assert is_login_destination_allowed("http://127.0.0.1:9011/auth", page)
    assert not is_login_destination_allowed("http://127.0.0.1:9015/auth", page)
    assert not is_login_destination_allowed("http://127.0.0.2/auth", page)
    assert is_login_destination_allowed(
        "http://127.0.0.1:9015/auth", page, Scope(Request("http://127.0.0.1:9015/"), "folder")
    )
