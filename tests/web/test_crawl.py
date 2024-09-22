from urllib.parse import urlparse, parse_qs
from tempfile import TemporaryDirectory
from shutil import rmtree
from asyncio import Event

import respx
import httpx
import pytest

from wapitiCore.net import Request
from wapitiCore.controller.wapiti import Wapiti


@pytest.mark.asyncio
@respx.mock
async def test_resume_crawling():
    stop_event = Event()

    def process(http_request):
        try:
            page = int(parse_qs(urlparse(str(http_request.url)).query)["page"][0])
        except (IndexError, KeyError, ValueError):
            return httpx.Response(200, text="Invalid value")

        if page == 10:
            stop_event.set()

        if page > 20:
            return httpx.Response(200, text="")

        body = "<html><body>"
        body += "<a href='http://perdu.com/?page={0}'>{0}</a>\n".format(page + 1)
        body += "<a href='http://perdu.com/?page={0}'>{0}</a>\n".format(page + 2)
        return httpx.Response(200, text=body)

    respx.get(url__regex=r"http://perdu\.com/$").mock(
        return_value=httpx.Response(200, text="<html><body><a href='http://perdu.com/?page=0'>0</a>")
    )

    respx.get(url__regex=r"http://perdu\.com/\?page=\d+").mock(side_effect=process)

    # Mock HTTP 404 behavior check
    respx.get(url__regex=r"http://perdu\.com/z.*\.html$").mock(return_value=httpx.Response(404))

    temp_obj = TemporaryDirectory()
    wapiti = Wapiti(Request("http://perdu.com/"), session_dir=temp_obj.name)
    await wapiti.init_persister()
    await wapiti.load_scan_state()
    await wapiti.browse(stop_event, parallelism=1)
    await wapiti.save_scan_state()
    remaining_requests = set([request async for request in wapiti.persister.get_to_browse()])
    # Got root url + pages 0 to 9
    all_requests = set([request async for request, __ in wapiti.persister.get_links()])
    remaining_urls = {request.url for request in remaining_requests - all_requests}
    # Page 10 stops the crawling but gave links to pages 11 and 12 so they will be the remaining urls
    assert remaining_urls == {"http://perdu.com/?page=11", "http://perdu.com/?page=12"}

    wapiti = Wapiti(Request("http://perdu.com/"), session_dir=temp_obj.name)
    await wapiti.init_persister()
    await wapiti.load_scan_state()
    await wapiti.browse(stop_event)
    await wapiti.save_scan_state()
    remaining_requests = set([request async for request in wapiti.persister.get_to_browse()])
    all_requests = set([request async for request, __ in wapiti.persister.get_links()])
    # We stop giving new links at page > 20 but page 20 will give urls for 21 and 22
    # so, we have 24 paginated pages (23 from 0 to 22) + root url here
    assert len(all_requests) == 24
    # We are done as we scanned all the pages
    assert not remaining_requests - all_requests
    rmtree(temp_obj.name)
