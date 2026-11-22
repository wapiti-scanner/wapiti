"""Tests of the forms filled by the headless crawler, with a real browser."""
import json

import pytest
from playwright.async_api import async_playwright

from wapitiCore.net import Request
from wapitiCore.net.intercepting_explorer import click_in_webpage, get_autofill_value, get_button_fingerprint

BASE_URL = "http://wapiti.test/"

# Fields have no name and the button is not inside the form, as seen on websites building their requests in JS
LOGIN_BLOCK = """
<div class="modal-content">
  <div class="modal-body">
    <form>
      <input type="text" id="loginusername">
      <input type="password" id="loginpassword">
      <input type="text" id="prefilled" value="keep me">
      <input type="text" id="invisible" style="display: none">
      <input type="checkbox" id="terms">
      <select id="country"><option value="">Choose</option><option value="fr">France</option></select>
      <textarea id="comment"></textarea>
    </form>
  </div>
  <div class="modal-footer">
    <button type="button" onclick="logIn()">Log in</button>
  </div>
</div>
<script>
function logIn() {
  const data = {};
  for (const id of ["loginusername", "loginpassword", "prefilled", "invisible", "country", "comment"]) {
    data[id] = document.getElementById(id).value;
  }
  data.terms = document.getElementById("terms").checked;
  fetch("/api/login", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(data)});
}
</script>
"""

# The form only shows up once a link of the menu was clicked, and the first button of the modal closes it
MODAL_PAGE = """<html><body>
<a href="#" data-toggle="modal" onclick="document.getElementById('modal').style.display = 'block'">Sign up</a>
<a href="#" onclick="fetch('/api/category')">Phones</a>
<a href="/away.html">A real link</a>
<div id="modal" style="display: none">
  <div class="modal-header">
    <button type="button" class="close" data-dismiss="modal"
      onclick="fetch('/api/dismissed'); document.getElementById('modal').style.display = 'none'">x</button>
  </div>
  <div class="modal-body"><form><input type="text" id="sign-username"></form></div>
  <div class="modal-footer">
    <button type="button"
      onclick="fetch('/api/signup?user=' + document.getElementById('sign-username').value)">Sign up</button>
  </div>
</div>
</body></html>"""

PAGES = {
    "": f"<html><body>{LOGIN_BLOCK}<button onclick=\"fetch('/api/next')\">Next</button></body></html>",
    "other.html": f"<html><body>{LOGIN_BLOCK}<button onclick=\"fetch('/api/next')\">Next</button></body></html>",
    "other.html?page=2": "<html><body><button onclick=\"fetch('/api/next')\">Next</button></body></html>",
    "native.html": """<html><body>
        <form action="/api/native" method="POST">
          <input type="text" name="q"><button>Classic</button>
        </form>
        <form onsubmit="fetch('/api/ajax?q=' + this.q.value); return false">
          <input type="text" name="q"><button>Ajax</button>
        </form>
        </body></html>""",
    "navigate.html": """<html><body>
        <button onclick="location.href = '/away.html'">Leave</button>
        <button onclick="fetch('/api/after-leave')">Stay</button>
        </body></html>""",
    "away.html": "<html><body>Somewhere else</body></html>",
    "modal.html": MODAL_PAGE,
    "modal2.html": MODAL_PAGE,
}


async def crawl_pages(*paths: str) -> list:
    """Load each page and click in it, returns the (method, path, body) of what was sent to /api/."""
    api_calls = []

    async def handle_route(route):
        path = route.request.url.removeprefix(BASE_URL)
        if path.startswith("api/"):
            api_calls.append((route.request.method, path, route.request.post_data))
            await route.fulfill(status=200, content_type="text/plain", body="ok")
        else:
            await route.fulfill(status=200, content_type="text/html", body=PAGES[path])

    seen_fingerprints = set()
    async with async_playwright() as playwright:
        browser = await playwright.firefox.launch(headless=True)
        try:
            page = await browser.new_page()
            await page.route("**/*", handle_route)
            for path in paths:
                await page.goto(BASE_URL + path)
                await click_in_webpage(
                    page, Request(BASE_URL + path), wait_time=1., timeout=5., seen_fingerprints=seen_fingerprints
                )
        finally:
            await browser.close()

    return api_calls


@pytest.mark.asyncio
async def test_fields_are_filled_before_the_click():
    api_calls = await crawl_pages("")

    login_calls = [call for call in api_calls if call[1] == "api/login"]
    assert len(login_calls) == 1
    assert json.loads(login_calls[0][2]) == {
        "loginusername": "alice",
        "loginpassword": "Letm3in_",
        "prefilled": "keep me",
        "invisible": "",
        "terms": True,
        "country": "fr",
        "comment": "Hi there!",
    }


@pytest.mark.asyncio
async def test_same_form_is_submitted_once_for_the_whole_crawl():
    api_calls = await crawl_pages("", "other.html", "other.html?page=2")
    paths = [call[1] for call in api_calls]

    # The login form is on two pages but its fields are the same
    assert paths.count("api/login") == 1
    # A button without fields is clicked once per path, whatever the query string is
    assert paths.count("api/next") == 2


@pytest.mark.asyncio
async def test_forms_submitted_by_the_crawler_are_not_clicked():
    api_calls = await crawl_pages("native.html")

    # The form with an action is extracted from the HTML and sent by the crawler, only the JS one needs a click
    assert [call[1] for call in api_calls] == ["api/ajax?q=default"]


@pytest.mark.asyncio
async def test_buttons_are_still_clicked_after_a_navigation():
    api_calls = await crawl_pages("navigate.html")

    assert [call[1] for call in api_calls] == ["api/after-leave"]


@pytest.mark.asyncio
async def test_hidden_forms_are_revealed_by_triggers():
    api_calls = await crawl_pages("modal.html")
    paths = [call[1] for call in api_calls]

    # The modal was opened, its form filled and submitted, and the button closing it was left alone
    assert sorted(paths) == ["api/category", "api/signup?user=alice"]


@pytest.mark.asyncio
async def test_triggers_are_clicked_once_for_the_whole_crawl():
    api_calls = await crawl_pages("modal.html", "modal2.html")
    paths = [call[1] for call in api_calls]

    assert paths.count("api/category") == 1
    assert paths.count("api/signup?user=alice") == 1


def test_get_autofill_value():
    assert get_autofill_value("text", "sign-username") == "alice"
    assert get_autofill_value("text", "contact mail") == "wapiti2021@mailinator.com"
    assert get_autofill_value("password", "") == "Letm3in_"
    assert get_autofill_value("textarea", "") == "Hi there!"
    assert get_autofill_value("number", "quantity") == "1337"


def test_get_button_fingerprint():
    form_info = {"buttonKey": "button:logIn()", "fields": [{"key": "text:user"}, {"key": "password:pass"}]}
    bare_info = {"buttonKey": "button:next", "fields": []}

    assert get_button_fingerprint(form_info, Request("http://perdu.com/a")) == get_button_fingerprint(
        form_info, Request("http://perdu.com/b")
    )
    assert get_button_fingerprint(bare_info, Request("http://perdu.com/a?x=1")) == get_button_fingerprint(
        bare_info, Request("http://perdu.com/a?x=2")
    )
    assert get_button_fingerprint(bare_info, Request("http://perdu.com/a")) != get_button_fingerprint(
        bare_info, Request("http://perdu.com/b")
    )
    assert get_button_fingerprint(bare_info, Request("http://perdu.com/a"), is_trigger=True) == (
        get_button_fingerprint(bare_info, Request("http://perdu.com/b"), is_trigger=True)
    )
