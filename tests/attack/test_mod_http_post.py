from unittest.mock import Mock
from asyncio import Event

import respx
import httpx
import pytest

from wapitiCore.net.web import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_http_post import mod_http_post
from wapitiCore.language.vulnerability import _
from tests import AsyncMock


@pytest.mark.asyncio
@respx.mock

async def test_no_login_form():
    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
                <h2>Pas de panique, on va vous aider</h2> \
                <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong></body></html>"
        )
    )
    persister = AsyncMock()

    request = Request("http://perdu.com/")
    request.path_id = 1
    # persister.requests.append(request)

    crawler = AsyncCrawler("http://perdu.com/")

    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_http_post(crawler, persister, options, Event())
    module.verbose = 2

    await module.attack(request)

    assert not persister.add_payload.call_count
    await crawler.close()

@pytest.mark.asyncio
@respx.mock
async def test_login_form_https():
    url = "https://perdu.com/"
    body = """<html>
        <body>
        <form method="POST">
        <input type="text" name="username" />
        <input type="password" name="pass" />
        </form>
        </body>
        </html>
        """

    respx.get(url).mock(return_value=httpx.Response(200, text=body))

    persister = AsyncMock()
    request = Request("https://perdu.com/")
    request.path_id = 1
    # persister.requests.append(request)

    crawler = AsyncCrawler("https://perdu.com/")

    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_http_post(crawler, persister, options, Event())
    module.verbose = 2

    await module.attack(request)
    assert not persister.add_payload.call_count
    await crawler.close()

@pytest.mark.asyncio
@respx.mock
async def test_login_form_http():
    url = "http://perdu.com/"
    body = """<html>
        <body>
        <form method="POST">
        <input type="text" name="username" />
        <input type="password" name="pass" value="Letm3in_" />
        </form>
        </body>
        </html>
        """

    respx.get(url).mock(return_value=httpx.Response(200, text=body))

    persister = AsyncMock()
    request = Request(
        "http://perdu.com/",
        method="POST",
        post_params=[["email", "wapiti2021@mailinator.com"], ["password", "Letm3in_"]],
    )
    request.path_id = 1
    # persister.requests.append(request)

    crawler = AsyncCrawler("http://perdu.com/")

    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_http_post(crawler, persister, options, Event())
    module.verbose = 2

    await module.attack(request)
    assert persister.add_payload.call_count
    assert persister.add_payload.call_args_list[0][1]["module"] == "http_post"
    assert persister.add_payload.call_args_list[0][1]["category"] == _("POST HTTP")
    await crawler.close()
