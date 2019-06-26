import os

import responses

from wapitiCore.net.sqlite_persister import SqlitePersister
from wapitiCore.net.web import Request
from wapitiCore.net.crawler import Crawler


try:
    os.unlink("/tmp/crawl.db")
except FileNotFoundError:
    pass


@responses.activate
def test_persister():

    url = "http://httpbin.org/?k=v"
    responses.add(
        responses.GET,
        url,
        body="Hello world!"
    )

    crawler = Crawler("http://httpbin.org/")

    persister = SqlitePersister("/tmp/crawl.db")
    persister.set_root_url("http://httpbin.org/")

    simple_get = Request("http://httpbin.org/?k=v")

    simple_post = Request(
        "http://httpbin.org/post?var1=a&var2=b",
        post_params=[["post1", "c"], ["post2", "d"]]
    )
    persister.set_to_browse([simple_get, simple_post])

    simple_upload = Request(
        "http://httpbin.org/post?qs1",
        post_params=[["post1", "c"], ["post2", "d"]],
        file_params=[["file1", ["'fname1", "content"]], ["file2", ["fname2", "content"]]]
    )
    persister.add_request(simple_upload)

    assert persister.get_root_url() == "http://httpbin.org/"
    assert persister.count_paths() == 3
    assert not len(list(persister.get_links()))
    assert not len(list(persister.get_forms()))
    assert not len(list(persister.get_payloads()))

    stored_requests = set(persister.get_to_browse())
    assert simple_get in stored_requests
    assert simple_post in stored_requests
    assert simple_upload in stored_requests

    # If there is some requests stored then it means scan was started
    assert persister.has_scan_started()
    assert not persister.has_scan_finished()
    assert not persister.have_attacks_started()

    for req in stored_requests:
        if req == simple_get:
            crawler.send(req)
            persister.add_request(req)
            assert req.path_id == 1
            assert persister.get_path_by_id(1) == req
            break

    # Should be one now as the link was crawled
    assert len(list(persister.get_links()))
    assert persister.count_paths() == 4

    persister.set_attacked(1, "xss")
    assert persister.count_attacked("xss") == 1
    assert persister.have_attacks_started()

    naughty_get = Request("http://httpbin.org/?k=1%20%OR%200")
    persister.add_vulnerability(1, "SQL Injection", 1, naughty_get, "k", "OR bypass")
    assert next(persister.get_payloads())
    persister.flush_attacks()
    assert not persister.have_attacks_started()
    assert not len(list(persister.get_payloads()))
    persister.flush_session()
    assert not persister.count_paths()
