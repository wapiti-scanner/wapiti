from urllib.parse import urlparse, parse_qs
from tempfile import NamedTemporaryFile
import sqlite3
from asyncio import Event
from unittest.mock import AsyncMock

import httpx
import respx
import pytest

from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net import Request
from wapitiCore.net.crawler import AsyncCrawler
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

        module = ModuleSql(crawler, persister, options, Event(), crawler_configuration)
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

        module = ModuleSql(crawler, persister, options, Event(), crawler_configuration)
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

        module = ModuleSql(crawler, persister, options, Event(), crawler_configuration)
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
            else:
                conn = sqlite3.connect(database_fd.name)
                cursor = conn.cursor()
                try:
                    # Will you spot the SQLi vulnerability? :D
                    cursor.execute("SELECT username FROM users WHERE id = {}".format(user_id))
                    row = cursor.fetchone()
                except sqlite3.OperationalError:
                    cursor.close()
                    conn.close()
                    return httpx.Response(200, text="Unknown user")
                else:
                    cursor.close()
                    conn.close()
                    if row:
                        return httpx.Response(200, text="Welcome {}".format(row[0]))
                    else:
                        return httpx.Response(200, text="Unknown user")

        respx.get(url__regex=r"http://perdu\.com/\?user_id=.*").mock(side_effect=process)

        persister = AsyncMock()

        request = Request("http://perdu.com/?user_id=1")
        request.path_id = 1

        crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
        async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
            options = {"timeout": 10, "level": 1}

            module = ModuleSql(crawler, persister, options, Event(), crawler_configuration)
            module.do_post = True
            await module.attack(request)

            assert persister.add_payload.call_count
            # One request for error-based, one to get normal response, four to test boolean-based attack
            assert respx.calls.call_count == 6


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

        module = ModuleSql(crawler, persister, options, Event(), crawler_configuration)
        await module.attack(request)

        assert not persister.add_payload.call_count
        # We have:
        # - 1 request for error-based test
        # - 1 request to get normal response
        # - 2*3 requests for the first test of each "session" (as the first test fails others are skipped)
        assert respx.calls.call_count == 8


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
            else:
                conn = sqlite3.connect(database_fd.name)
                cursor = conn.cursor()
                try:
                    # Will you spot the SQLi vulnerability? :D
                    cursor.execute("SELECT id FROM users WHERE username = '{}'".format(username))
                    row = cursor.fetchone()
                except sqlite3.OperationalError:
                    cursor.close()
                    conn.close()
                    return httpx.Response(200, text="Unknown user")
                else:
                    cursor.close()
                    conn.close()
                    if row:
                        return httpx.Response(200, text="Welcome, your user ID is {}".format(row[0]))
                    else:
                        return httpx.Response(200, text="Unknown user")

        respx.get(url__regex=r"http://perdu\.com/\?username=.*").mock(side_effect=process)

        persister = AsyncMock()

        request = Request("http://perdu.com/?username=admin")
        request.path_id = 1

        crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
        async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
            options = {"timeout": 10, "level": 1}

            module = ModuleSql(crawler, persister, options, Event(), crawler_configuration)
            module.do_post = True
            await module.attack(request)

            assert persister.add_payload.call_count
            # We have:
            # - 1 request for error-based test
            # - 1 request to get normal response
            # - 2 requests for boolean False test without parenthesis
            # - 1 request for boolean True test without parenthesis => this check fails
            # - 2 requests for boolean False test WITH parenthesis
            # - 2 requests for boolean True test WITH parenthesis
            assert respx.calls.call_count == 9
