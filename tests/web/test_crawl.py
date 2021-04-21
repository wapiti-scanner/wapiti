import re
from urllib.parse import urlparse, parse_qs
from tempfile import TemporaryDirectory
from shutil import rmtree
from asyncio import Event

import responses
import pytest

from wapitiCore.main.wapiti import Wapiti


@pytest.fixture
def mocked_responses():
    with responses.RequestsMock() as rsps:
        yield rsps


@pytest.mark.asyncio
async def test_resume_crawling(mocked_responses):
    stop_event = Event()

    def process(http_request):
        try:
            page = int(parse_qs(urlparse(http_request.url).query)["page"][0])
        except (IndexError, KeyError, ValueError):
            return 200, {}, "Invalid value"

        if page == 10:
            stop_event.set()

        if page > 20:
            return 200, {}, ""

        body = "<html><body>"
        body += "<a href='http://perdu.com/?page={0}'>{0}</a>\n".format(page + 1)
        body += "<a href='http://perdu.com/?page={0}'>{0}</a>\n".format(page + 2)
        return 200, {}, body

    mocked_responses.add(
        responses.GET,
        re.compile(r"http://perdu\.com/$"),
        body="<html><body><a href='http://perdu.com/?page=0'>0</a>"
    )

    mocked_responses.add_callback(
        responses.GET,
        re.compile(r"http://perdu.com/\?page=\d+"),
        callback=process
    )

    temp_obj = TemporaryDirectory()
    wapiti = Wapiti("http://perdu.com/", session_dir=temp_obj.name)
    wapiti.load_scan_state()
    await wapiti.browse(stop_event, parallelism=1)
    wapiti.save_scan_state()
    remaining_requests = set(wapiti.persister.get_to_browse())
    # Got root url + pages 0 to 9
    all_requests = set(wapiti.persister.get_links())
    remaining_urls = {request.url for request in (remaining_requests - all_requests)}
    # Page 10 gave error, page 11 was in task queue so it was processed, it remains pages 12 and 13
    assert remaining_urls == {"http://perdu.com/?page=12", "http://perdu.com/?page=13"}

    wapiti = Wapiti("http://perdu.com/", session_dir=temp_obj.name)
    wapiti.load_scan_state()
    stop_event.clear()
    await wapiti.browse(stop_event)
    wapiti.save_scan_state()
    remaining_requests = set(wapiti.persister.get_to_browse())
    all_requests = set(wapiti.persister.get_links())
    # We stop giving new links at page > 20 but page 20 will give urls for 21 and 22
    # so we have 24 paginated pages (23 from 0 to 22) + root url here
    assert len(all_requests) == 24
    # We are done as we scanned all the pages
    assert not (remaining_requests - all_requests)
    rmtree(temp_obj.name)
