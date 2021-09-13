import os
from asyncio import Event
from itertools import chain

import httpx
import respx
import pytest

from wapitiCore.net.web import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.language.vulnerability import _
from wapitiCore.attack.mod_nikto import mod_nikto
from tests import AsyncMock


@pytest.mark.asyncio
@respx.mock
async def test_whole_stuff():
    # Test attacking all kind of parameter without crashing
    respx.route(host="raw.githubusercontent.com").pass_through()

    respx.get("http://perdu.com/cgi-bin/a1disp3.cgi?../../../../../../../../../../etc/passwd").mock(
        return_value=httpx.Response(200, text="root:0:0:")
    )

    respx.route(host="perdu.com").mock(
        return_value=httpx.Response(404, text="Not found")
    )

    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE")
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1
    request.status = 200
    request.set_headers({"content-type": "text/html"})
    persister.get_links.return_value = chain([request])

    crawler = AsyncCrawler("http://perdu.com/", timeout=1)
    options = {"timeout": 10, "level": 2, "tasks": 20}

    module = mod_nikto(crawler, persister, options, Event())
    module.do_get = True
    await module.attack(request)

    assert persister.add_payload.call_count == 1
    assert persister.add_payload.call_args_list[0][1]["module"] == "nikto"
    assert persister.add_payload.call_args_list[0][1]["category"] == _("Potentially dangerous file")
    assert persister.add_payload.call_args_list[0][1]["request"].url == (
        "http://perdu.com/cgi-bin/a1disp3.cgi?..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd"
    )
    assert (
               "This CGI allows attackers read arbitrary files on the host"
           ) in persister.add_payload.call_args_list[0][1]["info"]
    await crawler.close()
