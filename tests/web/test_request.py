import json

import respx
import httpx
import pytest

from wapitiCore.net.web import Request
from wapitiCore.net.crawler import AsyncCrawler


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
        "http://httpbin.org/post?qs1",
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
    assert res17.hostname == "example.com:8080"
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

    print("Tests were successful, now launching representations")
    print("=== Basic representation follows ===")
    print(res1)
    print("=== cURL representation follows ===")
    print(res1.curl_repr)
    print("=== HTTP representation follows ===")
    print(res1.http_repr())
    print("=== POST parameters as an array ===")
    print(res1.post_params)
    print("=== POST keys encoded as string ===")
    print(res1.encoded_post_keys)
    print("=== Upload HTTP representation  ===")
    print(res12.http_repr())
    print("=== Upload basic representation ===")
    print(res12)
    print("=== Upload cURL representation  ===")
    print(res12.curl_repr)
    print("===   HTTP GET keys as a tuple  ===")
    print(res1.get_keys)
    print("===  HTTP POST keys as a tuple  ===")
    print(res1.post_keys)
    print("=== HTTP files keys as a tuple  ===")
    print(res12.file_keys)
    print('')

    json_req = Request(
        "http://httpbin.org/post?a=b",
        post_params=json.dumps({"z": 1, "a": 2}),
        enctype="application/json"
    )

    crawler = AsyncCrawler("http://httpbin.org/")
    page = await crawler.async_send(json_req)
    assert page.json["json"] == {"z": 1, "a": 2}
    assert page.json["headers"]["Content-Type"] == "application/json"
    assert page.json["form"] == {}

    page = await crawler.async_send(res12)
    assert page.json["files"]

    res19 = Request(
        "http://httpbin.org/post?qs1",
        post_params=[['post1', 'c'], ['post2', 'd']],
        file_params=[['file1', ('fname1', b'content')], ['file2', ('fname2', b'content')]],
        enctype="multipart/form-data"
    )
    page = await crawler.async_send(res19)
    assert page.json["files"]
    await crawler.close()


@pytest.mark.asyncio
@respx.mock
async def test_redirect():
    slyfx = "http://www.slyfx.com/"
    disney = "http://www.disney.com/"

    respx.get(slyfx).mock(return_value=httpx.Response(301, headers={"Location": disney}, text="Back to disneyland"))
    respx.get(disney).mock(return_value=httpx.Response(200, text="Hello there"))

    crawler = AsyncCrawler(slyfx)
    page = await crawler.async_send(Request(slyfx))
    assert page.url == slyfx
    assert not page.history

    page = await crawler.async_send(Request(slyfx), follow_redirects=True)
    assert page.url == disney
    assert page.history[0].url == slyfx
    await crawler.close()
