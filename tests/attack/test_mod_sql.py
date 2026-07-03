import re
from urllib.parse import parse_qs
from tempfile import NamedTemporaryFile
import sqlite3
from unittest.mock import AsyncMock

import httpx
import respx
import pytest

from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.net.web import urlparse
from wapitiCore.attack.mod_sql import ModuleSql


@pytest.mark.asyncio
@respx.mock
async def test_whole_stuff():
    # Test attacking all kind of parameter without crashing
    respx.get(url__regex=r"http://perdu\.com/.*").mock(return_value=httpx.Response(200, text="Hello there"))
    respx.post(url__regex=r"http://perdu\.com/.*").mock(return_value=httpx.Response(200, text="Hello there"))

    persister = AsyncMock()
    all_requests = []

    request = Request("http://perdu.com/")
    request.path_id = 1
    all_requests.append(request)

    request = Request("http://perdu.com/?foo=bar")
    request.path_id = 2
    all_requests.append(request)

    request = Request(
        "http://perdu.com/?foo=bar",
        post_params=[["a", "b"]],
        file_params=[["file", ("calendar.xml", b"<xml>Hello there</xml", "application/xml")]]
    )
    request.path_id = 3
    all_requests.append(request)

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleSql(crawler, persister, options, crawler_configuration)
        module.do_post = True
        for request in all_requests:
            await module.attack(request)

        assert True


@pytest.mark.asyncio
@respx.mock
async def test_false_positive():
    respx.get("http://perdu.com/").mock(return_value=httpx.Response(200, text="You have an error in your SQL syntax"))

    persister = AsyncMock()

    request = Request("http://perdu.com/?foo=bar")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 1}

        module = ModuleSql(crawler, persister, options, crawler_configuration)
        module.do_post = True
        await module.attack(request)

        assert not persister.add_payload.call_count


@pytest.mark.asyncio
@respx.mock
async def test_true_positive():
    respx.get("http://perdu.com/?foo=bar").mock(return_value=httpx.Response(200, text="Hi there"))

    respx.get(url__regex=r"http://perdu\.com/\?foo=.*").mock(
        return_value=httpx.Response(
            200,
            text=(
                "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version "
                "for the right syntax to use near '\\\"\\'' at line 1"
            )
        )
    )

    persister = AsyncMock()

    request = Request("http://perdu.com/?foo=bar")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 1}

        module = ModuleSql(crawler, persister, options, crawler_configuration)
        module.do_post = True
        await module.attack(request)

        assert persister.add_payload.call_count
        assert persister.add_payload.call_args_list[0][1]["module"] == "sql"
        assert persister.add_payload.call_args_list[0][1]["category"] == "SQL Injection"


@pytest.mark.asyncio
@respx.mock
async def test_blind_detection():
    with NamedTemporaryFile() as database_fd:
        conn = sqlite3.connect(database_fd.name)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
        conn.commit()
        cursor.execute("INSERT INTO users (id, username, password) VALUES (1, \"admin\", \"123456\")")
        conn.commit()
        cursor.close()
        conn.close()

        def process(http_request):
            try:
                user_id = parse_qs(urlparse(str(http_request.url)).query)["user_id"][0]
            except (IndexError, KeyError):
                return httpx.Response(200, text="Unknown user")

            conn = sqlite3.connect(database_fd.name)
            cursor = conn.cursor()
            try:
                # Will you spot the SQLi vulnerability? :D
                cursor.execute(f"SELECT username FROM users WHERE id = {user_id}")
                row = cursor.fetchone()
            except sqlite3.OperationalError:
                cursor.close()
                conn.close()
                return httpx.Response(200, text="Unknown user")

            cursor.close()
            conn.close()
            if row:
                return httpx.Response(200, text=f"Welcome {row[0]}")
            return httpx.Response(200, text="Unknown user")

        respx.get(url__regex=r"http://perdu\.com/\?user_id=.*").mock(side_effect=process)

        persister = AsyncMock()

        request = Request("http://perdu.com/?user_id=1")
        request.path_id = 1

        crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
        async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
            options = {"timeout": 10, "level": 1}

            module = ModuleSql(crawler, persister, options, crawler_configuration)
            module.do_post = True
            await module.attack(request)

            assert persister.add_payload.call_count
            # One request for error-based, two to sample the normal response (stability check),
            # four to test boolean-based attack
            assert respx.calls.call_count == 7


@pytest.mark.asyncio
@respx.mock
async def test_negative_blind():
    respx.get("http://perdu.com/").mock(return_value=httpx.Response(200, text="Hello there"))

    persister = AsyncMock()

    request = Request("http://perdu.com/?foo=bar")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 1}

        module = ModuleSql(crawler, persister, options, crawler_configuration)
        await module.attack(request)

        assert not persister.add_payload.call_count
        # We have:
        # - 1 request for error-based test
        # - 2 requests to sample the normal response (stability check)
        # - 1 request for the first test of each of the 6 AND-based "sessions" (fails
        #   immediately, others are skipped)
        # - 3 requests for each of the 4 OR+comment-based "sessions" (the two "OR false"
        #   tests pass since the response matches the baseline either way, the first
        #   "OR true" test then fails and the last one is skipped)
        assert respx.calls.call_count == 21


@pytest.mark.asyncio
@respx.mock
async def test_blind_detection_parenthesis():
    with NamedTemporaryFile() as database_fd:
        conn = sqlite3.connect(database_fd.name)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
        conn.commit()
        cursor.execute("INSERT INTO users (id, username, password) VALUES (1, \"admin\", \"123456\")")
        conn.commit()
        cursor.close()
        conn.close()

        def process(http_request):
            try:
                username = parse_qs(urlparse(str(http_request.url)).query)["username"][0]
            except (IndexError, KeyError):
                return httpx.Response(200, text="Unknown user")

            conn = sqlite3.connect(database_fd.name)
            cursor = conn.cursor()
            try:
                # Will you spot the SQLi vulnerability? :D
                cursor.execute(f"SELECT id FROM users WHERE username = '{username}'")
                row = cursor.fetchone()
            except sqlite3.OperationalError:
                cursor.close()
                conn.close()
                return httpx.Response(200, text="Unknown user")

            cursor.close()
            conn.close()
            if row:
                return httpx.Response(200, text=f"Welcome, your user ID is {row[0]}")
            return httpx.Response(200, text="Unknown user")

        respx.get(url__regex=r"http://perdu\.com/\?username=.*").mock(side_effect=process)

        persister = AsyncMock()

        request = Request("http://perdu.com/?username=admin")
        request.path_id = 1

        crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
        async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
            options = {"timeout": 10, "level": 1}

            module = ModuleSql(crawler, persister, options, crawler_configuration)
            module.do_post = True
            await module.attack(request)

            assert persister.add_payload.call_count
            # We have:
            # - 1 request for error-based test
            # - 2 requests to sample the normal response (stability check)
            # - 2 requests for boolean False test without parenthesis
            # - 1 request for boolean True test without parenthesis => this check fails
            # - 2 requests for boolean False test WITH parenthesis
            # - 2 requests for boolean True test WITH parenthesis
            assert respx.calls.call_count == 10


@pytest.mark.asyncio
@respx.mock
async def test_no_false_positive_when_rate_limited():
    # Regression test: a server that rate-limits us (HTTP 429) on the "false" boolean
    # requests must not be reported as vulnerable. A 429 differs from the normal page,
    # which would otherwise satisfy a false-section test and produce a false positive.
    def process(http_request):
        query = urlparse(str(http_request.url)).query
        values = " ".join(value for values in parse_qs(query).values() for value in values)
        pairs = re.findall(r"(\d+)=(\d+)", values)
        # A boolean "false" payload compares two different numbers (e.g. AND 13=37)
        if any(left != right for left, right in pairs):
            return httpx.Response(429, text="Too Many Requests")
        return httpx.Response(200, text="Hello there")

    respx.get(url__regex=r"http://perdu\.com/.*").mock(side_effect=process)

    persister = AsyncMock()

    request = Request("http://perdu.com/?foo=bar")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 1}

        module = ModuleSql(crawler, persister, options, crawler_configuration)
        await module.attack(request)

        # Without the rate-limit guard, the "false" tests would pass (429 != normal page)
        # and the "true" tests too, yielding a false positive.
        assert not persister.add_payload.call_count


@pytest.mark.asyncio
@respx.mock
async def test_detection_via_or_comment_payload_when_and_based_fails():
    # Regression test: some injectable parameters (e.g. a login field compared against a
    # value that structurally never matches any row, or matched via a LIKE pattern) make
    # the AND-based technique blind: appending "AND true/false" never changes the outcome,
    # since the original condition was already false. An OR-based payload that comments
    # out the rest of the query can still prove the injection, by making the condition
    # unconditionally true (e.g. a login bypass) instead of relying on the original
    # condition ever matching.
    def process(http_request):
        query = urlparse(str(http_request.url)).query
        values = " ".join(value for values in parse_qs(query).values() for value in values)
        match = re.search(r"OR (\d+)=(\d+)", values)
        if match and match.group(1) == match.group(2):
            return httpx.Response(200, text="Session opened!")
        return httpx.Response(200, text="Invalid login!")

    respx.get(url__regex=r"http://perdu\.com/.*").mock(side_effect=process)

    persister = AsyncMock()

    request = Request("http://perdu.com/?foo=bar")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 1}

        module = ModuleSql(crawler, persister, options, crawler_configuration)
        await module.attack(request)

        assert persister.add_payload.call_count


@pytest.mark.asyncio
@respx.mock
async def test_detection_despite_unrelated_dynamic_content():
    # A page can carry small per-request dynamic content unrelated to the injected value
    # (e.g. a CSRF token) without being genuinely "unstable": the same boolean outcome
    # should still be considered a match even though the two responses aren't byte-for-byte
    # identical. This is the original motivation for the similarity ratio, now that it's
    # safe from reflection-driven false positives (see the reflected-payload test above).
    filler = "Lorem ipsum dolor sit amet consectetur " * 5
    counter = {"n": 0}

    def process(http_request):
        counter["n"] += 1
        query = urlparse(str(http_request.url)).query
        values = " ".join(value for values in parse_qs(query).values() for value in values)
        pairs = re.findall(r"(\d+)=(\d+)", values)
        matched = not pairs or all(left == right for left, right in pairs)
        tail = (
            "Result: something interesting was found here in the database" if matched
            else "Sorry, absolutely nothing matched your search criteria today"
        )
        return httpx.Response(200, text=f"{filler}<input type='hidden' value='csrf-{counter['n']}'>{tail}")

    respx.get(url__regex=r"http://perdu\.com/.*").mock(side_effect=process)

    persister = AsyncMock()

    request = Request("http://perdu.com/?foo=bar")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 1}

        module = ModuleSql(crawler, persister, options, crawler_configuration)
        await module.attack(request)

        assert persister.add_payload.call_count


@pytest.mark.asyncio
@respx.mock
async def test_no_false_positive_when_payload_is_reflected():
    # Regression test: a page that reflects the injected value back verbatim (e.g. a
    # search page showing "You searched for '<value>'") makes the "true" and "false"
    # responses differ from the baseline by construction, even when the underlying SQL
    # behaves identically both times (e.g. no results either way). A fuzzy similarity
    # ratio can be fooled into treating this superficial difference as a real signal;
    # an exact match on the visible text is not.
    def process(http_request):
        query = urlparse(str(http_request.url)).query
        value = parse_qs(query).get("foo", [""])[0]
        return httpx.Response(200, text=f"You searched for '{value}', no results")

    respx.get(url__regex=r"http://perdu\.com/.*").mock(side_effect=process)

    persister = AsyncMock()

    request = Request("http://perdu.com/?foo=bar")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 1}

        module = ModuleSql(crawler, persister, options, crawler_configuration)
        await module.attack(request)

        assert not persister.add_payload.call_count


@pytest.mark.asyncio
@respx.mock
async def test_detection_when_false_payload_triggers_server_error():
    # Regression test: a server that returns HTTP 500 on the "false" boolean requests
    # (e.g. a broken injected query crashing the backend) is a genuine SQLi signal and
    # must still be reported as vulnerable, unlike a 429 rate-limit response.
    def process(http_request):
        query = urlparse(str(http_request.url)).query
        values = " ".join(value for values in parse_qs(query).values() for value in values)
        pairs = re.findall(r"(\d+)=(\d+)", values)
        # A boolean "false" payload compares two different numbers (e.g. AND 13=37)
        if any(left != right for left, right in pairs):
            return httpx.Response(500, text="Internal Server Error")
        return httpx.Response(200, text="Hello there")

    respx.get(url__regex=r"http://perdu\.com/.*").mock(side_effect=process)

    persister = AsyncMock()

    request = Request("http://perdu.com/?foo=bar")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 1}

        module = ModuleSql(crawler, persister, options, crawler_configuration)
        await module.attack(request)

        # The 500 on "false" payloads differs from the stable baseline, confirming the
        # boolean test just like a normal differing page would.
        assert persister.add_payload.call_count


@pytest.mark.asyncio
@respx.mock
async def test_no_false_positive_on_dynamic_page():
    # Regression test: a page whose content changes between two identical requests is
    # dynamic. Boolean comparison cannot be trusted, so detection must be skipped instead
    # of producing false results.
    counter = {"n": 0}

    def process(http_request):
        counter["n"] += 1
        return httpx.Response(200, text="unique dynamic content " + "x" * (counter["n"] * 100))

    respx.get(url__regex=r"http://perdu\.com/.*").mock(side_effect=process)

    persister = AsyncMock()

    request = Request("http://perdu.com/?foo=bar")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 1}

        module = ModuleSql(crawler, persister, options, crawler_configuration)
        await module.attack(request)

        assert not persister.add_payload.call_count
        # 1 error-based request + 2 baseline samples that differ => boolean detection skipped
        assert respx.calls.call_count == 3
