import re
from urllib.parse import urlparse, parse_qs
from tempfile import TemporaryDirectory
from shutil import rmtree

import responses

from wapitiCore.main.wapiti import Wapiti


@responses.activate
def test_resume_crawling():

    def process(http_request):
        try:
            page = int(parse_qs(urlparse(http_request.url).query)["page"][0])
        except (IndexError, KeyError, ValueError):
            return 200, {}, "Invalid value"

        if page == 10:
            raise KeyboardInterrupt("Stop here")

        if page > 20:
            return 200, {}, ""

        body = "<html><body>"
        body += "<a href='http://perdu.com/?page={0}'>{0}</a>\n".format(page + 1)
        body += "<a href='http://perdu.com/?page={0}'>{0}</a>\n".format(page + 2)
        return 200, {}, body

    responses.add(
        responses.GET,
        re.compile(r"http://perdu\.com/$"),
        body="<html><body><a href='http://perdu.com/?page=0'>0</a>"
    )

    responses.add_callback(
        responses.GET,
        re.compile(r"http://perdu.com/\?page=\d+"),
        callback=process
    )

    temp_obj = TemporaryDirectory()
    wapiti = Wapiti("http://perdu.com/", session_dir=temp_obj.name)
    wapiti.browse()
    remaining_requests = set(wapiti.persister.get_to_browse())
    # Got root url + pages 0 to 9
    all_requests = set(wapiti.persister.get_links())
    remaning_request = (remaining_requests - all_requests).pop()
    # Page 10 gave error so the only one left should be 9 or 11 depending which one was taken first
    assert remaning_request.url in ("http://perdu.com/?page=9", "http://perdu.com/?page=11")

    wapiti = Wapiti("http://perdu.com/", session_dir=temp_obj.name)
    wapiti.browse()
    remaining_requests = set(wapiti.persister.get_to_browse())
    all_requests = set(wapiti.persister.get_links())
    # We stop giving new links at page > 20 but page 20 will give urls for 21 and 22
    # so we have 22 paginated pages + root url here
    assert len(all_requests) == 23
    # We are done as we scanned all the pages
    assert not (remaining_requests - all_requests)
    rmtree(temp_obj.name)
