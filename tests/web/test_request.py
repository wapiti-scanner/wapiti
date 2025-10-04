import json
import os
from subprocess import Popen
from time import sleep
import sys

import respx
import httpx
import pytest

from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net import Request
from wapitiCore.net.crawler import AsyncCrawler, Response as WapitiResponse
from wapitiCore.net.web import http_repr, curl_repr


@pytest.fixture(autouse=True)
def run_around_tests():
    base_dir = os.path.dirname(sys.modules["wapitiCore"].__file__)
    test_directory = os.path.join(base_dir, "..", "tests/data/")

    proc = Popen(["php", "-S", "127.0.0.1:65084", "-a", "-t", test_directory])
    sleep(.5)
    yield
    proc.terminate()


@pytest.mark.asyncio
async def test_request_object():
    res1 = Request(
        "http://httpbin.org/post?var1=a&var2=b",
        post_params=[['post1', 'c'], ['post2', 'd']]
    )

    res2 = Request(
        "http://httpbin.org/post?var1=a&var2=z",
        post_params=[['post1', 'c'], ['post2', 'd']]
    )

    res3 = Request(
        "http://httpbin.org/post?var1=a&var2=b",
        post_params=[['post1', 'c'], ['post2', 'z']]
    )

    res4 = Request(
        "http://httpbin.org/post?var1=a&var2=b",
        post_params=[['post1', 'c'], ['post2', 'd']]
    )

    res5 = Request(
        "http://httpbin.org/post?var1=z&var2=b",
        post_params=[['post1', 'c'], ['post2', 'd']]
    )

    res6 = Request(
        "http://httpbin.org/post?var3=z&var2=b",
        post_params=[['post1', 'c'], ['post2', 'd']]
    )

    res7 = Request(
        "http://httpbin.org/post?var1=z&var2=b&var4=e",
        post_params=[['post1', 'c'], ['post2', 'd']]
    )

    res8 = Request(
        "http://httpbin.org/post?var2=d&var1=z",
        post_params=[['post1', 'c'], ['post2', 'd']]
    )

    res10 = Request(
        "http://httpbin.org/post?qs0",
        post_params=[['post1', 'c'], ['post2', 'd']]
    )

    res11 = Request(
        "http://httpbin.org/post?qs1",
        post_params=[['post1', 'c'], ['post2', 'd']]
    )

    res12 = Request(
        "http://127.0.0.1:65084/httpbin.php?qs1",
        post_params=[['post1', 'c'], ['post2', 'd']],
        file_params=[['file1', ('fname1', b'content')], ['file2', ('fname2', b'content')]]
    )

    res13 = Request("https://www.youtube.com/user/OneMinuteSilenceBand/videos")
    res14 = Request("https://www.youtube.com/user/OneMinuteSilenceBand/")
    res15 = Request("https://duckduckgo.com/")
    res16 = Request("https://duckduckgo.com/", post_params=[['q', 'Kung Fury']])
    res17 = Request("http://example.com:8080/dir/?x=3")

    res18 = Request(
        "http://httpbin.org/get?a=1",
        get_params=[['get1', 'c'], ['get2', 'd']]
    )

    assert res1 < res2
    assert res2 > res3
    assert res1 < res3
    assert res1 == res4
    assert hash(res1) == hash(res4)
    res4.link_depth = 5
    assert hash(res1) == hash(res4)
    assert res1 != res2
    assert res2 >= res1
    assert res1 <= res3
    assert res13.file_name == "videos"
    assert res10.path == "http://httpbin.org/post"
    assert res10.file_name == "post"
    # This one is important as it could break attacks on query string
    assert res10.url == "http://httpbin.org/post?qs0"
    assert res13.parent_dir == res14.url
    assert res15.is_root
    assert res15.parent_dir == res15.url
    assert res13.dir_name == res14.url
    assert res14.dir_name == res14.url
    assert res15.dir_name == res15.url
    assert res15 != res16
    query_list = [res15]
    assert res16 not in query_list
    assert res17.dir_name == "http://example.com:8080/dir/"
    assert res18.url == "http://httpbin.org/get?get1=c&get2=d"
    assert res17.hostname == "example.com"
    assert res17.netloc == "example.com:8080"
    assert res17.port == 8080
    assert res1.encoded_get_keys == res8.encoded_get_keys
    assert res17.encoded_get_keys == "x"
    assert res16.encoded_get_keys == ""
    assert res12.parameters_count == 5
    assert res12.encoded_get_keys == "qs1"
    assert res5.hash_params == res8.hash_params
    assert res7.hash_params != res8.hash_params

    assert res6 in [res6, res11]
    assert res6 not in [res11, None]
    assert res11 in [res6, res11]
    assert res11 not in [None, res6]

    json_req = Request(
        "http://127.0.0.1:65084/httpbin.php?a=b",
        post_params=json.dumps({"z": 1, "a": 2}),
        enctype="application/json"
    )

    crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:65084/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        response = await crawler.async_send(json_req)
        assert response.json["json"] == {"z": 1, "a": 2}
        assert response.json["headers"]["Content-Type"] == "application/json"
        assert response.json["form"] == []  # PHP dictionaries are array too

        response = await crawler.async_send(res12)
        assert response.json["files"]

        res19 = Request(
            "http://127.0.0.1:65084/httpbin.php?qs1",
            post_params=[['post1', 'c'], ['post2', 'd']],
            file_params=[['file1', ('fname1', b'content')], ['file2', ('fname2', b'content')]],
            enctype="multipart/form-data"
        )
        response = await crawler.async_send(res19)
        assert response.json["files"]


@pytest.mark.asyncio
@respx.mock
async def test_redirect():
    slyfx = "http://www.slyfx.com/"
    disney = "http://www.disney.com/"

    respx.get(slyfx).mock(return_value=httpx.Response(301, headers={"Location": disney}, text="Back to disneyland"))
    respx.get(disney).mock(return_value=httpx.Response(200, text="Hello there"))

    crawler_configuration = CrawlerConfiguration(Request(slyfx))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        response = await crawler.async_send(Request(slyfx))
        assert response.url == slyfx
        assert not response.history

        response = await crawler.async_send(Request(slyfx), follow_redirects=True)
        assert response.url == disney
        assert response.history[0].url == slyfx


def test_request_headers():
    req = Request("http://perdu.com/")
    assert req.headers == httpx.Headers()

    # Test add_header
    req.add_header("User-Agent", "Wapiti/3.x")
    assert req.headers["User-Agent"] == "Wapiti/3.x"

    # Test update_headers with a dict
    req.update_headers({"Accept-Language": "en-US", "Accept-Encoding": "gzip, deflate"})
    assert req.headers["User-Agent"] == "Wapiti/3.x"
    assert req.headers["Accept-Language"] == "en-US"
    assert req.headers["Accept-Encoding"] == "gzip, deflate"

    # Test update_headers with a list of tuples
    req.update_headers([("Connection", "keep-alive"), ("Accept", "text/html")])
    assert req.headers["Connection"] == "keep-alive"
    assert req.headers["Accept"] == "text/html"

    # Test updating an existing header with add_header
    req.add_header("User-Agent", "Mozilla/5.0")
    assert req.headers["User-Agent"] == "Mozilla/5.0"

    # Test case-insensitivity of headers
    assert req.headers["user-agent"] == "Mozilla/5.0"


@pytest.mark.parametrize(
    "request_, expected_output, sent_headers_to_set",
    [
        (
            Request("http://perdu.com/index.php?a=1"),
            '''GET /index.php?a=1 HTTP/1.1''',
            None
        ),
        (
            Request("http://perdu.com/", method="POST", post_params=[["foo", "bar"]]),
            '''POST / HTTP/1.1
    Content-Type: application/x-www-form-urlencoded

    foo=bar''',
            None
        ),
        (
            Request(
                "http://perdu.com/",
                method="POST",
                post_params=[['post1', 'c']],
                file_params=[['file1', ('fname1', b'content')]]
            ),
            '''POST / HTTP/1.1
    Content-Type: multipart/form-data; boundary=------------------------boundarystring

    ------------------------boundarystring
    Content-Disposition: form-data; name="post1"

    c
    ------------------------boundarystring
    Content-Disposition: form-data; name="file1"; filename="fname1"

    content
    ------------------------boundarystring--''',
            None
        ),
        (
            Request(
                "http://perdu.com/",
                method="POST",
                post_params=json.dumps({"a": 1}),
                enctype="application/json"
            ),
            '''POST / HTTP/1.1
    Content-Type: application/json

    {"a": 1}''',
            None
        ),
        (
            Request("http://perdu.com/", headers={"User-Agent": "Wapiti"}),
            '''GET / HTTP/1.1
    user-agent: Wapiti''',
            None
        ),
        (
            Request("http://perdu.com/", headers={"User-Agent": "Wapiti"}),
            '''GET / HTTP/1.1
    user-agent: Custom''',
            httpx.Headers({"User-Agent": "Custom"})
        ),
    ]
)
def test_http_repr(request_, expected_output, sent_headers_to_set):
    if sent_headers_to_set:
        request_.set_sent_headers(sent_headers_to_set)
    output = http_repr(request_).strip()
    assert output == expected_output


@pytest.mark.parametrize(
    "request_, expected_output",
    [
        (
            Request("http://perdu.com/index.php?a=1"),
            'curl "http://perdu.com/index.php?a=1"'
        ),
        (
            Request("http://perdu.com/", referer="http://google.com/"),
            'curl "http://perdu.com/" -e "http://google.com/"'
        ),
        (
            Request("http://perdu.com/", method="POST", post_params=[["foo", "bar"]]),
            'curl "http://perdu.com/" -d "foo=bar"'
        ),
        (
            Request(
                "http://perdu.com/",
                method="POST",
                post_params=[["foo", "bar"]],
                file_params=[["file", ("test.txt", b"content")]]
            ),
            'curl "http://perdu.com/" -F "foo=bar" -F "file=@your_local_file;filename=test.txt"'
        ),
        (
            Request(
                "http://perdu.com/",
                method="POST",
                post_params=json.dumps({"a": 1}),
                enctype="application/json"
            ),
            'curl "http://perdu.com/" -H "Content-Type: application/json" -d @payload_file'
        ),
    ]
)
def test_curl_repr(request_, expected_output):
    assert curl_repr(request_) == expected_output
