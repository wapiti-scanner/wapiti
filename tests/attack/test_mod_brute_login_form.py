import pytest
import respx
import httpx
from unittest.mock import AsyncMock, patch

from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net import Request
from wapitiCore.net.response import Response
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_brute_login_form import ModuleBruteLoginForm


LOGIN_FORM_HTML = """
<html><body>
<form action=\"/login\" method=\"post\">
  <input type=\"text\" name=\"username\">
  <input type=\"password\" name=\"password\">
  <input type=\"submit\" value=\"Login\">
</form>
</body></html>
"""

LOGIN_FAILURE_PAGE = "<html><body>Login failed</body></html>"
LOGIN_SUCCESS_PAGE = "<html><body>Welcome admin! You are logged in.</body></html>"


@pytest.mark.asyncio
async def test_must_attack():
    module = ModuleBruteLoginForm(None, None, {}, None)

    # Case 1: A valid request that should be attacked
    request_ok = Request("http://perdu.com/", post_params=[["p", "Letm3in_"]], referer="http://perdu.com/login")
    response_ok = Response(httpx.Response(status_code=200, text="body"), url="http://perdu.com/")
    assert await module.must_attack(request_ok, response_ok) is True

    # Case 2: No "Letm3in_" placeholder
    request_ko_payload = Request("http://perdu.com/", post_params=[["p", "secret"]], referer="http://perdu.com/login")
    assert await module.must_attack(request_ko_payload, response_ok) is False

    # Case 3: No referer
    request_ko_referer = Request("http://perdu.com/", post_params=[["p", "Letm3in_"]])
    assert await module.must_attack(request_ko_referer, response_ok) is False

    # Case 4: Directory redirection response
    request_dir_redir = Request("http://perdu.com/login", post_params=[["p", "Letm3in_"]], referer="http://perdu.com/login")
    response_dir_redir = Response(
        httpx.Response(status_code=301, headers={"Location": "http://perdu.com/login/"}),
        url="http://perdu.com/login"
    )
    assert await module.must_attack(request_dir_redir, response_dir_redir) is False


@pytest.mark.asyncio
@respx.mock
@patch.object(ModuleBruteLoginForm, "check_success_auth", side_effect=lambda c: "You are logged in" in c)
@patch.object(ModuleBruteLoginForm, "get_passwords", return_value=["password", "admin"])
@patch.object(ModuleBruteLoginForm, "get_usernames", return_value=["user", "admin"])
async def test_login_success(_, __, ___):
    def login_callback(request):
        data = request.content.decode()
        if "username=admin" in data and "password=admin" in data:
            return httpx.Response(200, text=LOGIN_SUCCESS_PAGE)
        return httpx.Response(200, text=LOGIN_FAILURE_PAGE)

    respx.get("http://perdu.com/login").mock(return_value=httpx.Response(200, text=LOGIN_FORM_HTML))
    respx.post("http://perdu.com/login").mock(side_effect=login_callback)

    persister = AsyncMock()

    # This request simulates a form submitted by the crawler where a password field was detected
    request = Request(
        "http://perdu.com/some_page",
        method="POST",
        post_params=[["user", "foo"], ["password", "Letm3in_"]],
        referer="http://perdu.com/login"
    )
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 1, "tasks": 20}

        module = ModuleBruteLoginForm(crawler, persister, options, crawler_configuration)

        await module.attack(request)

        assert persister.add_payload.call_count == 1
        call_kwargs = persister.add_payload.call_args.kwargs
        assert "Credentials found" in call_kwargs["info"]
        assert "admin / admin" in call_kwargs["info"]

        evil_request = call_kwargs["request"]
        assert evil_request.method == "POST"
        assert evil_request.post_params == [["username", "admin"], ["password", "admin"]]
