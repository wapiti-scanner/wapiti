from urllib.parse import parse_qs
from tempfile import TemporaryDirectory
from shutil import rmtree
from asyncio import Event

import respx
import httpx
import pytest

from wapitiCore.net import Request
from wapitiCore.net.web import urlparse
from wapitiCore.controller.wapiti import Wapiti


def page_numbers(requests) -> set:
    """Returns the numbers of the paginated pages among the given requests (the root URL has none)."""
    pages = set()
    for request in requests:
        query = parse_qs(urlparse(request.url).query)
        if "page" in query:
            pages.add(int(query["page"][0]))
    return pages


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
        body += f"<a href='http://perdu.com/?page={page + 1}'>{page + 1}</a>\n"
        body += f"<a href='http://perdu.com/?page={page + 2}'>{page + 2}</a>\n"
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
    remaining_requests = {request async for request in wapiti.persister.get_to_browse()}
    all_requests = {request async for request, __ in wapiti.persister.get_links()}
    visited_pages = page_numbers(all_requests)
    remaining_pages = page_numbers(remaining_requests - all_requests)
    # Page 10 stops the crawling. Requests already scheduled at that moment are still sent, and how many of them
    # there are depends on the event loop timing, so we can't expect an exact list of crawled pages here.
    assert 10 in visited_pages
    # No request is scheduled once the crawling is stopped, so the links found afterwards are never followed
    assert max(visited_pages) <= 11
    assert 12 in remaining_pages
    # Whatever the timing was, each link found on a crawled page must either be crawled or kept for the next run
    found_pages = {page + offset for page in visited_pages for offset in (1, 2)}
    assert remaining_pages == found_pages - visited_pages

    wapiti = Wapiti(Request("http://perdu.com/"), session_dir=temp_obj.name)
    await wapiti.init_persister()
    await wapiti.load_scan_state()
    await wapiti.browse(stop_event)
    await wapiti.save_scan_state()
    remaining_requests = {request async for request in wapiti.persister.get_to_browse()}
    all_requests = {request async for request, __ in wapiti.persister.get_links()}
    # We stop giving new links at page > 20 but page 20 will give urls for 21 and 22
    # so, we have 24 paginated pages (23 from 0 to 22) + root url here
    assert len(all_requests) == 24
    # We are done as we scanned all the pages
    assert not remaining_requests - all_requests
    rmtree(temp_obj.name)
