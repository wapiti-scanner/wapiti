"""Bounded crawl tests for the per-endpoint raw body budget (review of #819).

A raw body (JSON, XML, GraphQL...) has no parameter name, so ``Request.parameters_count``
is 0 and ``has_too_many_parameters`` never applies to it. These tests drive the real
admission paths to check that the number of such requests kept for one endpoint stays
bounded: the standard crawler is exercised through ``async_explore`` against a fake
transport (respx, no socket is opened), the intercepting one through ``process_requests``
fed with in-memory request/response pairs (no proxy, no browser).

The budget is also part of the crawl state, which the crawler now stores as JSON: the
tuple buckets and the byte digests are therefore written as explicit records and read
back with the same checks.
"""

import asyncio
import hashlib
import json
from collections import defaultdict, deque

import httpx
import pytest
import respx

from wapitiCore.net import Request
from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net.explorer import MAX_RAW_BODIES_PER_ENDPOINT, Explorer
from wapitiCore.net.response import Response
from wapitiCore.net.scope import Scope
from wapitiCore.net.sql_persister import SqlPersister

BASE = "http://example.test"
OTHER = "http://other.test"
API = BASE + "/api"
JSON_BUCKET = ("POST", API, "application/json")
CAP = MAX_RAW_BODIES_PER_ENDPOINT


def raw(body: str, enctype: str = "application/json", path: str = "/api", method: str = "POST",
        base: str = BASE, fragment: str = "") -> Request:
    return Request(base + path + fragment, method=method, post_params=body, enctype=enctype)


def digest_of(body: str) -> str:
    """The digest the budget keeps for a body, in the hex form the state file uses."""
    return hashlib.blake2b(body.encode("utf-8", "surrogatepass"), digest_size=16).hexdigest()


def make_explorer() -> Explorer:
    return Explorer(
        CrawlerConfiguration(Request(BASE + "/")),
        Scope(Request(BASE + "/"), "folder"),
        asyncio.Event(),
    )


def state_file(tmp_path, name: str = "crawl.json") -> str:
    return (tmp_path / name).as_posix()


def write_state(path: str, raw_body_counts, hostnames=None):
    """Write a state file the crawler would have produced, with an arbitrary budget part."""
    payload = {
        "file_counts": {BASE + "/": 3},
        "pattern_counts": {},
        "hostnames": sorted(hostnames or {"example.test"}),
    }
    if raw_body_counts is not ...:
        payload["raw_body_counts"] = raw_body_counts
    with open(path, "w", encoding="utf-8") as file_data:
        json.dump(payload, file_data)


async def explore(batches, explorer: Explorer = None):
    """Run the standard crawler admission + send path on a fake transport.

    Returns the requests actually sent, the (request, response) pairs yielded to the
    persister and the explorer used (its budget state can then be inspected).
    """
    explorer = explorer or make_explorer()
    sent = []
    yielded = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(
            {
                "method": request.method,
                "url": str(request.url),
                "body": request.content.decode("utf-8", "replace"),
            }
        )
        return httpx.Response(200, content=b"ok", headers={"Content-Type": "text/plain"})

    with respx.mock(assert_all_mocked=True, assert_all_called=False) as router:
        router.route(url__startswith=BASE + "/").mock(side_effect=handler)
        router.route(url__startswith=OTHER + "/").mock(side_effect=handler)
        try:
            for batch in batches:
                async for request, response in explorer.async_explore(deque(batch)):
                    yielded.append((request, response))
        finally:
            await explorer.clean()

    return sent, yielded, explorer


def posted_bodies(sent) -> list:
    """Bodies of the requests really handed to the transport (the soft-404 probe has none)."""
    return [item["body"] for item in sent if item["body"]]


def yielded_bodies(yielded) -> list:
    """Bodies of the requests yielded to the persister, sorted: the crawl sends in parallel."""
    return sorted(request.post_params for request, _ in yielded)


@pytest.mark.asyncio
async def test_standard_crawl_admits_at_most_cap_distinct_raw_bodies_per_endpoint():
    bodies = [f'{{"n":{index}}}' for index in range(15)]

    sent, yielded, explorer = await explore([[raw(body) for body in bodies]])

    assert CAP == 10
    assert sorted(posted_bodies(sent)) == sorted(bodies[:CAP])
    assert yielded_bodies(yielded) == sorted(bodies[:CAP])
    # Nothing was stored for the rejected bodies, and the state of the endpoint is bounded.
    assert len(explorer._raw_body_counts[JSON_BUCKET]) == CAP


@pytest.mark.asyncio
async def test_persisted_rows_and_attack_input_stop_at_the_same_cap(tmp_path):
    bodies = [f'{{"n":{index}}}' for index in range(15)]

    _sent, yielded, _explorer = await explore([[raw(body) for body in bodies]])

    persister = SqlPersister((tmp_path / "crawl.db").as_posix())
    await persister.create()
    try:
        await persister.set_root_url(BASE + "/")
        await persister.save_requests(yielded)
        assert await persister.count_paths() == CAP
        # What the attack modules get back is bounded by the same admission decision.
        forms = [request async for request, _response in persister.get_forms()]
        assert len(forms) == CAP
        assert sorted(request.post_params for request in forms) == sorted(bodies[:CAP])
    finally:
        await persister.close()


@pytest.mark.asyncio
async def test_duplicate_raw_body_takes_no_extra_slot():
    admitted = [f'{{"n":{index}}}' for index in range(9)]
    # Same body and same endpoint as admitted[0], but a distinct request identity: the fragment
    # is part of Request identity (and not part of the URL that is sent), so the identity check
    # cannot drop it. Going through admission therefore proves the duplicate took no slot.
    duplicate = raw(admitted[0], fragment="#again")
    assert (duplicate == raw(admitted[0])) is False
    assert duplicate.path == raw(admitted[0]).path
    assert duplicate.url == raw(admitted[0]).url

    sent, yielded, explorer = await explore([[
        *[raw(body) for body in admitted],
        duplicate,
        raw('{"n":"tenth"}'),
        raw('{"n":"eleventh"}'),
    ]])

    # The 10th distinct body still fits, the 11th does not: the duplicate consumed nothing.
    assert yielded_bodies(yielded) == sorted(admitted + [admitted[0], '{"n":"tenth"}'])
    assert len(explorer._raw_body_counts[JSON_BUCKET]) == CAP
    assert '{"n":"eleventh"}' not in posted_bodies(sent)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "variant",
    [
        {"method": "PUT"},
        {"path": "/other"},
        {"base": OTHER},
        {"enctype": "text/xml"},
        {"enctype": "application/problem+json"},
    ],
    ids=["method", "path", "origin", "content-type", "other-json-media-type"],
)
async def test_budget_is_isolated_per_method_origin_path_and_content_type(variant):
    saturated = [raw(f'{{"n":{index}}}') for index in range(CAP)]
    neighbour = raw('{"neighbour":1}', **variant)

    _sent, yielded, explorer = await explore([saturated, [neighbour]])

    # The saturated endpoint stays bounded while the neighbour endpoint gets its own budget.
    assert len(yielded) == CAP + 1
    assert '{"neighbour":1}' in yielded_bodies(yielded)
    assert len(explorer._raw_body_counts) == 2
    assert len(explorer._raw_body_counts[JSON_BUCKET]) == CAP


@pytest.mark.asyncio
async def test_content_type_parameters_share_one_budget():
    plain = [raw(f'{{"n":{index}}}', enctype="application/json") for index in range(9)]
    parameterized = [
        raw('{"c":0}', enctype="application/json; charset=utf-8"),
        raw('{"c":1}', enctype="Application/JSON ; charset=UTF-8"),
        raw('{"c":2}', enctype="application/json;charset=latin1"),
    ]

    _sent, yielded, explorer = await explore([plain + parameterized])

    # 9 + 1 admitted, the two last ones share the very same media type budget.
    assert len(yielded) == CAP
    assert list(explorer._raw_body_counts) == [JSON_BUCKET]
    assert len(explorer._raw_body_counts[JSON_BUCKET]) == CAP


@pytest.mark.asyncio
async def test_form_and_multipart_requests_are_untouched_by_the_raw_body_budget():
    raw_bodies = [raw(f'{{"n":{index}}}') for index in range(12)]
    forms = [
        Request(API, method="POST", post_params=[["a", str(index)]],
                enctype="application/x-www-form-urlencoded")
        for index in range(12)
    ]
    uploads = [
        Request(BASE + "/upload", method="POST", file_params=[["f", (f"{index}.txt", "data")]])
        for index in range(12)
    ]

    _sent, yielded, explorer = await explore([raw_bodies, forms, uploads])

    assert len(yielded) == CAP + 12 + 12
    assert set(explorer._raw_body_counts) == {JSON_BUCKET}


@pytest.mark.asyncio
async def test_get_with_a_raw_body_is_budgeted_too():
    # A GET request may carry a raw body: the method name alone must not exempt it.
    bodies = [f'{{"n":{index}}}' for index in range(15)]

    sent, yielded, explorer = await explore([[raw(body, method="GET") for body in bodies]])

    assert yielded_bodies(yielded) == sorted(bodies[:CAP])
    assert len([item for item in sent if item["method"] == "GET" and item["url"] == API]) == CAP
    assert len(explorer._raw_body_counts[("GET", API, "")]) == CAP


@pytest.mark.asyncio
async def test_empty_body_is_not_a_raw_body():
    # Request turns an empty string body into an empty parameter list, so it is neither a raw
    # body nor a budget entry, exactly like a request without a body.
    empty = Request(API, method="POST", post_params="", enctype="application/json")
    assert empty.post_params == []
    assert Explorer._raw_body_bucket(empty) is None

    _sent, yielded, explorer = await explore([[
        *[raw(f'{{"n":{index}}}') for index in range(12)],
        empty,
    ]])

    assert len(yielded) == CAP + 1
    assert len(explorer._raw_body_counts[JSON_BUCKET]) == CAP


def test_state_file_is_json_with_explicit_budget_records(tmp_path):
    bodies = [f'{{"n":{index}}}' for index in range(3)]
    explorer = make_explorer()
    for body in bodies:
        assert explorer.has_enough_raw_bodies(raw(body)) is False
    explorer._file_counts[BASE + "/"] = 2
    explorer._hostnames.add("example.test")

    path = state_file(tmp_path)
    explorer.save_state(path)

    with open(path, "r", encoding="utf-8") as file_data:
        state = json.load(file_data)

    # The three inherited keys keep their meaning, the budget is one explicit record.
    assert set(state) == {"file_counts", "pattern_counts", "hostnames", "raw_body_counts"}
    assert state["file_counts"] == {BASE + "/": 2}
    assert state["hostnames"] == ["example.test"]
    assert state["raw_body_counts"] == [
        {
            "method": "POST",
            "path": API,
            "media_type": "application/json",
            "digests": sorted(digest_of(body) for body in bodies),
        }
    ]
    # 32 lowercase hex digits per digest: bytes are not stored as bytes, tuples not as keys.
    for digest in state["raw_body_counts"][0]["digests"]:
        assert len(digest) == 32
        assert digest == digest.lower()
        assert int(digest, 16) >= 0


@pytest.mark.asyncio
async def test_resume_does_not_regrant_the_budget(tmp_path):
    path = state_file(tmp_path)
    admitted = [f'{{"n":{index}}}' for index in range(12)]

    _sent, yielded, explorer = await explore([[raw(body) for body in admitted]])
    assert len(yielded) == CAP
    explorer.save_state(path)

    resumed = make_explorer()
    resumed.load_saved_state(path)
    assert resumed._raw_body_counts == explorer._raw_body_counts

    _sent, yielded, _resumed = await explore(
        [[raw(admitted[0]), raw('{"fresh":1}'), raw(admitted[11])]], explorer=resumed
    )

    # Already admitted bodies are not dropped, but no endpoint gets a fresh set of slots.
    assert [request.post_params for request, _ in yielded] == [admitted[0]]
    assert len(resumed._raw_body_counts[JSON_BUCKET]) == CAP


def test_budget_survives_a_json_save_and_load_round_trip(tmp_path):
    path = state_file(tmp_path)
    bodies = [f'{{"n":{index}}}' for index in range(CAP)]
    explorer = make_explorer()
    for body in bodies:
        explorer.has_enough_raw_bodies(raw(body))
    explorer.save_state(path)

    with open(path, "r", encoding="utf-8") as file_data:
        assert len(json.load(file_data)["raw_body_counts"][0]["digests"]) == CAP

    resumed = make_explorer()
    resumed.load_saved_state(path)
    assert resumed._raw_body_counts == explorer._raw_body_counts
    # Restored as bytes of the right length, so the cap logic compares them to new digests.
    assert {len(digest) for digest in resumed._raw_body_counts[JSON_BUCKET]} == {16}


def test_legacy_json_without_budget_key_still_loads(tmp_path):
    path = state_file(tmp_path, "legacy.json")
    write_state(path, ...)  # the three keys the previous version wrote

    explorer = make_explorer()
    explorer.load_saved_state(path)

    assert explorer._raw_body_counts == {}
    assert explorer._file_counts[BASE + "/"] == 3
    assert explorer._hostnames == {"example.test"}
    # Such a state has no budget at all: the endpoint starts a fresh one, as documented.
    assert explorer.has_enough_raw_bodies(raw('{"n":0}')) is False


@pytest.mark.parametrize(
    "budget",
    [
        pytest.param({"method": "POST"}, id="not-a-list"),
        pytest.param(None, id="null"),
        pytest.param(["nope"], id="record-not-a-dict"),
        pytest.param(
            [{"method": "POST", "path": API, "media_type": "application/json"}], id="missing-digests"
        ),
        pytest.param(
            [{"method": "POST", "path": API, "media_type": "application/json", "digests": [], "extra": 1}],
            id="extra-field",
        ),
        pytest.param(
            [{"method": 7, "path": API, "media_type": "application/json", "digests": []}], id="non-string-method"
        ),
        pytest.param(
            [{"method": "POST", "path": "", "media_type": "application/json", "digests": []}], id="empty-path"
        ),
        pytest.param(
            [{"method": "POST", "path": API, "media_type": "application/json",
              "digests": [digest_of("x").upper()]}],
            id="uppercase-digest",
        ),
        pytest.param(
            [{"method": "POST", "path": API, "media_type": "application/json",
              "digests": [digest_of("x")[:31]]}],
            id="short-digest",
        ),
        pytest.param(
            [{"method": "POST", "path": API, "media_type": "application/json", "digests": ["z" * 32]}],
            id="non-hex-digest",
        ),
        pytest.param(
            [{"method": "POST", "path": API, "media_type": "application/json",
              "digests": [digest_of(str(index)) for index in range(CAP + 1)]}],
            id="over-cap",
        ),
        pytest.param(
            [
                {"method": "POST", "path": API, "media_type": "application/json",
                 "digests": [digest_of(str(index)) for index in range(6)]},
                {"method": "POST", "path": API, "media_type": "application/json",
                 "digests": [digest_of(str(index)) for index in range(6, CAP + 1)]},
            ],
            id="duplicate-records-over-cap",
        ),
    ],
)
def test_invalid_budget_records_are_refused_instead_of_reset(tmp_path, budget):
    """A budget the state cannot prove is refused: dropping it would recreate free slots."""
    path = state_file(tmp_path)
    write_state(path, budget)

    explorer = make_explorer()
    with pytest.raises(ValueError):
        explorer.load_saved_state(path)

    # Refusal is all-or-nothing: no part of the state is applied either.
    assert explorer._raw_body_counts == {}
    assert explorer._file_counts == {}
    assert explorer._hostnames == set()


def test_duplicate_records_for_one_endpoint_merge_up_to_the_cap(tmp_path):
    path = state_file(tmp_path)
    first = [digest_of(f"a{index}") for index in range(6)]
    second = [digest_of(f"b{index}") for index in range(4)]
    write_state(
        path,
        [
            {"method": "POST", "path": API, "media_type": "application/json", "digests": first},
            {"method": "POST", "path": API, "media_type": "application/json", "digests": second},
        ],
    )

    explorer = make_explorer()
    explorer.load_saved_state(path)

    # Both records name the same endpoint: they are merged, and the merged bucket is full.
    assert set(explorer._raw_body_counts) == {JSON_BUCKET}
    assert len(explorer._raw_body_counts[JSON_BUCKET]) == CAP
    assert explorer.has_enough_raw_bodies(raw('{"n":"overflow"}')) is True
    # A digest of one of the records is still known, so it is not a new variant.
    assert explorer.has_enough_raw_bodies(raw("a0")) is False


@pytest.mark.asyncio
async def test_rejected_body_is_absent_from_the_saved_state(tmp_path):
    path = state_file(tmp_path)
    bodies = [f'{{"n":{index}}}' for index in range(15)]

    _sent, _yielded, explorer = await explore([[raw(body) for body in bodies]])
    explorer.save_state(path)

    with open(path, "r", encoding="utf-8") as file_data:
        content = file_data.read()
    state = json.loads(content)

    saved = state["raw_body_counts"][0]["digests"]
    assert saved == sorted(digest_of(body) for body in bodies[:CAP])
    for rejected in bodies[CAP:]:
        assert digest_of(rejected) not in saved
        # The body itself is never written, only its digest.
        assert rejected not in content


def fill_intercept_queue(explorer, requests):
    """Put in-memory (request, response) pairs in the queue the proxy addon would fill."""
    explorer._queue = asyncio.Queue()
    for request in requests:
        response = Response(
            httpx.Response(200, content=b"ok", headers={"Content-Type": "text/plain"}),
            url=request.url,
        )
        explorer._queue.put_nowait((request, response))


async def drain_intercept_queue(explorer):
    """Drain process_requests: it is the admission point of the intercepting crawler."""
    explorer._stopped.set()
    return [request async for request, _response in explorer.process_requests(set(), [])]


@pytest.mark.asyncio
async def test_intercepting_explorer_bounds_admitted_raw_bodies_and_file_budget():
    # mitmproxy and playwright are runtime dependencies of wapiti but are not installed in every
    # local environment: skip (not pass) when the module cannot be imported.
    intercepting_explorer = pytest.importorskip("wapitiCore.net.intercepting_explorer")

    bodies = [f'{{"n":{index}}}' for index in range(15)]
    explorer = intercepting_explorer.InterceptingExplorer(
        CrawlerConfiguration(Request(BASE + "/")),
        Scope(Request(BASE + "/"), "folder"),
        asyncio.Event(),
        headless="hidden",
        seed_fallback=False,
    )
    fill_intercept_queue(explorer, [raw(body) for body in bodies])

    admitted = await drain_intercept_queue(explorer)

    assert [request.post_params for request in admitted] == bodies[:CAP]
    # Rejected bodies were refused before the per-directory file budget was consumed.
    assert dict(explorer._file_counts) == {BASE + "/": CAP}


@pytest.mark.asyncio
async def test_intercepting_explorer_keeps_form_requests_untouched():
    intercepting_explorer = pytest.importorskip("wapitiCore.net.intercepting_explorer")

    explorer = intercepting_explorer.InterceptingExplorer(
        CrawlerConfiguration(Request(BASE + "/")),
        Scope(Request(BASE + "/"), "folder"),
        asyncio.Event(),
        headless="hidden",
        seed_fallback=False,
    )
    fill_intercept_queue(
        explorer,
        [
            *[raw(f'{{"n":{index}}}') for index in range(12)],
            *[
                Request(API, method="POST", post_params=[["a", str(index)]],
                        enctype="application/x-www-form-urlencoded")
                for index in range(3)
            ],
        ],
    )

    admitted = await drain_intercept_queue(explorer)

    assert len(admitted) == CAP + 3
    assert dict(explorer._file_counts) == {BASE + "/": CAP + 3}
