import asyncio
from collections import deque

import httpx
import pytest
import respx

from wapitiCore.net import Request
from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net.explorer import Explorer
from wapitiCore.net.response import Response
from wapitiCore.net.scope import Scope
from wapitiCore.net.sql_persister import SqlPersister

BASE = "http://example.test"


def raw(body: str, enctype: str = "application/json", path: str = "/api", method: str = "POST") -> Request:
    return Request(BASE + path, method=method, post_params=body, enctype=enctype)


@pytest.mark.parametrize(
    ("body_a", "body_b", "enctype"),
    [
        ('{"a":1}', '{"b":1}', "application/json"),
        ('{"a":1}', '{"a":2}', "application/json"),
        ("<a>1</a>", "<b>2</b>", "text/xml"),
        ("alpha-a", "alpha-b", "text/plain"),
        ('{"é":1}', '{"è":1}', "application/json"),
    ],
    ids=["json-keys", "json-values", "xml", "text", "unicode"],
)
def test_distinct_equal_length_raw_bodies_stay_distinct(body_a, body_b, enctype):
    assert len(body_a) == len(body_b)
    first = raw(body_a, enctype)
    second = raw(body_b, enctype)

    assert first != second
    assert (first == second) is False
    assert len({first, second}) == 2
    assert len({first: "first", second: "second"}) == 2


def test_same_raw_body_with_different_content_type_stays_distinct():
    first = raw('{"a":1}', "application/json")
    second = raw('{"a":1}', "application/problem+json")

    assert first != second
    assert len({first, second}) == 2


def test_exact_raw_body_duplicates_remain_equal_and_hashable():
    first = raw('{"a":1}')
    duplicate = raw('{"a":1}')

    assert first == duplicate
    assert (first != duplicate) is False
    assert hash(first) == hash(duplicate)
    assert len({first, duplicate}) == 1
    assert len({first: "first", duplicate: "duplicate"}) == 1


@pytest.mark.parametrize(
    ("path", "method"),
    [("/other", "POST"), ("/api", "PUT")],
    ids=["different-path", "different-method"],
)
def test_raw_body_identity_still_includes_path_and_method(path, method):
    first = raw('{"a":1}')
    second = raw('{"a":1}', path=path, method=method)

    assert first != second
    assert len({first, second}) == 2


def test_ordered_list_form_params_keep_existing_identity_behavior():
    first = Request(
        BASE + "/form",
        method="POST",
        post_params=[["b", "2"], ["a", "1"]],
        enctype="application/x-www-form-urlencoded",
    )
    reordered = Request(
        BASE + "/form",
        method="POST",
        post_params=[["a", "1"], ["b", "2"]],
        enctype="application/x-www-form-urlencoded",
    )
    duplicate = Request(
        BASE + "/form",
        method="POST",
        post_params=[["b", "2"], ["a", "1"]],
        enctype="application/x-www-form-urlencoded",
    )

    assert first != reordered
    assert len({first, reordered}) == 2
    assert first == duplicate
    assert hash(first) == hash(duplicate)
    assert len({first, duplicate}) == 1


def test_hash_params_remains_the_separate_coarse_control():
    first = raw('{"a":1}')
    second = raw('{"b":1}')

    assert first.hash_params == second.hash_params


async def _explore(batches, excluded_urls=None):
    posts = []
    yielded = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "POST":
            posts.append(
                {
                    "url": str(request.url),
                    "body": request.content.decode("utf-8"),
                    "content_type": request.headers.get("content-type"),
                }
            )
        return httpx.Response(200, content=b"ok", headers={"Content-Type": "text/plain"})

    with respx.mock(assert_all_mocked=True, assert_all_called=False) as router:
        router.route(url__startswith=BASE + "/").mock(side_effect=handler)
        explorer = Explorer(
            CrawlerConfiguration(Request(BASE + "/")),
            Scope(Request(BASE + "/"), "folder"),
            asyncio.Event(),
        )
        try:
            for batch in batches:
                async for request, _response in explorer.async_explore(deque(batch), excluded_urls or []):
                    yielded.append(request.post_params)
        finally:
            await explorer.clean()

    return posts, yielded


@pytest.mark.asyncio
async def test_explorer_processed_state_admits_distinct_same_length_body():
    posts, yielded = await _explore([
        [raw('{"a":1}')],
        [raw('{"b":1}')],
    ])

    assert [post["body"] for post in posts] == ['{"a":1}', '{"b":1}']
    assert yielded == ['{"a":1}', '{"b":1}']


@pytest.mark.asyncio
async def test_explorer_processed_state_deduplicates_exact_body():
    posts, yielded = await _explore([
        [raw('{"a":1}')],
        [raw('{"a":1}')],
    ])

    assert [post["body"] for post in posts] == ['{"a":1}']
    assert yielded == ['{"a":1}']


@pytest.mark.asyncio
async def test_resume_exclusion_admits_distinct_same_length_body():
    posts, yielded = await _explore([[raw('{"b":1}')]], excluded_urls=[raw('{"a":1}')])

    assert [post["body"] for post in posts] == ['{"b":1}']
    assert yielded == ['{"b":1}']


@pytest.mark.asyncio
async def test_resume_exclusion_still_deduplicates_exact_body():
    posts, yielded = await _explore([[raw('{"a":1}')]], excluded_urls=[raw('{"a":1}')])

    assert posts == []
    assert yielded == []


@pytest.mark.parametrize(
    ("body", "path"),
    [('{"bb":1}', "/api"), ('{"b":1}', "/other")],
    ids=["different-length", "different-path"],
)
@pytest.mark.asyncio
async def test_resume_exclusion_negative_controls_are_admitted(body, path):
    posts, yielded = await _explore(
        [[raw(body, path=path)]],
        excluded_urls=[raw('{"a":1}')],
    )

    assert [post["body"] for post in posts] == [body]
    assert yielded == [body]


@pytest.mark.parametrize(
    ("pending_body", "expected_bodies"),
    [
        ('{"b":1}', ['{"b":1}']),
        ('{"a":1}', []),
    ],
    ids=["distinct-same-length", "exact-duplicate"],
)
@pytest.mark.asyncio
async def test_sql_persister_resume_admits_only_distinct_body(tmp_path, pending_body, expected_bodies):
    completed = raw('{"a":1}')
    pending = raw(pending_body)
    response = Response(
        httpx.Response(
            200,
            content=b"stored",
            headers={"Content-Type": "text/plain"},
            request=httpx.Request("POST", completed.url),
        ),
        url=completed.url,
    )
    database = (tmp_path / "crawl.db").as_posix()

    persister = SqlPersister(database)
    await persister.create()
    try:
        await persister.set_root_url(BASE + "/")
        await persister.save_request(completed, response)
        await persister.set_to_browse([pending])
    finally:
        await persister.close()

    persister = SqlPersister(database)
    await persister.create()
    try:
        forms = [request async for request, _response in persister.get_forms()]
        pending_requests = [request async for request in persister.get_to_browse()]
    finally:
        await persister.close()

    assert [request.post_params for request in forms] == ['{"a":1}']
    assert [request.post_params for request in pending_requests] == [pending_body]

    posts, yielded = await _explore([[pending_requests[0]]], excluded_urls=forms)
    assert [post["body"] for post in posts] == expected_bodies
    assert yielded == expected_bodies
