import asyncio
import json
import os
from asyncio import Event
from unittest.mock import patch, PropertyMock, AsyncMock

import httpx
import pytest
import respx

from wapitiCore.attack.mod_htp import ModuleHtp, get_matching_versions
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net import Request


@pytest.mark.asyncio
@respx.mock
async def test_must_attack():
    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE") or "/home"
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}
        module_htp = ModuleHtp(crawler, persister, options, Event(), crawler_configuration)

        assert await module_htp.must_attack(Request("http://perdu.com", method="POST")) is False
        assert await module_htp.must_attack(Request("http://perdu.com", method="GET")) is True


@pytest.mark.asyncio
@respx.mock
async def test_analyze_file_detection():
    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            200,
            text="foobar"
        )
    )

    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE") or "/home"
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1

    techno = "techno"
    techno_versions = {"versions": ["1.2", "1.2.1"]}

    with patch.object(ModuleHtp, "_find_technology", return_value=(techno, json.dumps(techno_versions))):
        crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
        async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
            options = {"timeout": 10, "level": 2}
            module_htp = ModuleHtp(crawler, persister, options, Event(), crawler_configuration)

            found_technology = await module_htp._analyze_file(Request("http://perdu.com/"))

            assert found_technology
            assert techno_versions == json.loads(found_technology[1])


@pytest.mark.asyncio
@respx.mock
async def test_analyze_file_no_detection():
    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            200,
            text="foobar"
        )
    )

    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE") or "/home"
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1

    with patch.object(ModuleHtp, "_find_technology", return_value=None):
        crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
        async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
            options = {"timeout": 10, "level": 2}
            module_htp = ModuleHtp(crawler, persister, options, Event(), crawler_configuration)

            assert await module_htp._analyze_file(Request("http://perdu.com")) is None


@pytest.mark.asyncio
@respx.mock
async def test_analyze_file_none_content():
    respx.get("http://perdu.com/").mock(
        return_value=None
    )

    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE") or "/home"
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}
        module_htp = ModuleHtp(crawler, persister, options, Event(), crawler_configuration)

        assert await module_htp._analyze_file(Request("http://perdu.com")) is None


@pytest.mark.asyncio
@respx.mock
async def test_analyze_file_request_error():
    respx.get("http://perdu.com/").mock(
        side_effect=httpx.RequestError("error")
    )

    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE") or "/home"
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}
        module_htp = ModuleHtp(crawler, persister, options, Event(), crawler_configuration)

        found_technology = await module_htp._analyze_file(Request("http://perdu.com"))

        assert found_technology is None
        assert module_htp.network_errors == 1


@pytest.mark.asyncio
@respx.mock
async def test_finish_no_technologies():
    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            200,
            text="foobar"
        )
    )

    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE") or "/home"
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1

    with patch("wapitiCore.attack.mod_htp.ModuleHtp.add_info", autospec=True) as mock_add_info, \
            patch.object(ModuleHtp, "_db", new_callable=PropertyMock) as mock_db:
        crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
        async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
            options = {"timeout": 10, "level": 2}
            module_htp = ModuleHtp(crawler, persister, options, Event(), crawler_configuration)

            await module_htp.finish()

            mock_db.assert_called()
            mock_add_info.assert_not_called()


@pytest.mark.asyncio
@respx.mock
async def test_finish_one_range():
    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            200,
            text="foobar"
        )
    )

    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE") or "/home"
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")
    persister.get_root_url.return_value = "http://perdu.com/"

    request = Request("http://perdu.com/")
    request.path_id = 1

    techno = "techno"

    versions = ["1.0", "1.1", "1.2", "1.2.1", "1.3", "1.4"]

    with patch.object(ModuleHtp, "_db", new_callable=PropertyMock), \
            patch.object(ModuleHtp, "_get_versions", return_value=versions):
        crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
        async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
            options = {"timeout": 10, "level": 2}
            module_htp = ModuleHtp(crawler, persister, options, Event(), crawler_configuration)
            module_htp._root_url = "http://perdu.com/"

            module_htp.tech_versions[techno] = [["1.2", "1.2.1", "1.3"]]

            await module_htp.finish()

            assert persister.add_payload.call_count
            assert persister.add_payload.call_args_list[0][1]["module"] == "htp"
            assert persister.add_payload.call_args_list[0][1]["payload_type"] == "vulnerability"
            assert persister.add_payload.call_args_list[0][1]["category"] == "Fingerprint web server"
            assert persister.add_payload.call_args_list[0][1]["level"] == 0
            assert persister.add_payload.call_args_list[0][1]["info"] == (
                '{"name": "techno", "versions": ["1.2", "1.2.1", "1.3"]}'
            )
            assert persister.add_payload.call_args_list[0][1]["wstg"] == ['WSTG-INFO-02']


@pytest.mark.asyncio
@respx.mock
async def test_finish_two_ranges():
    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            200,
            text="foobar"
        )
    )

    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE") or "/home"
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")
    persister.get_root_url.return_value = "http://perdu.com/"

    request = Request("http://perdu.com/")
    request.path_id = 1

    techno = "techno"

    versions = ["1.0", "1.1", "1.2", "1.2.1", "1.3", "1.4", "1.5", "1.6"]

    with patch.object(ModuleHtp, "_db", new_callable=PropertyMock), \
            patch.object(ModuleHtp, "_get_versions", return_value=versions):
        crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
        async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
            options = {"timeout": 10, "level": 2}
            module_htp = ModuleHtp(crawler, persister, options, Event(), crawler_configuration)
            module_htp._root_url = "http://perdu.com/"

            module_htp.tech_versions[techno] = [["1.2", "1.2.1", "1.3"], ["1.3", "1.4"], ["1.5", "1.5"], ["1.0", "1.2"]]

            await module_htp.finish()

            assert persister.add_payload.call_count
            assert persister.add_payload.call_args_list[0][1]["module"] == "htp"
            assert persister.add_payload.call_args_list[0][1]["payload_type"] == "vulnerability"
            assert persister.add_payload.call_args_list[0][1]["category"] == "Fingerprint web server"
            assert persister.add_payload.call_args_list[0][1]["level"] == 0
            assert persister.add_payload.call_args_list[0][1]["info"] == (
                '{"name": "techno", "versions": ["1.0", "1.1", "1.2", "1.2.1", "1.3", "1.4", "1.5"]}'
            )
            assert persister.add_payload.call_args_list[0][1]["wstg"] == ['WSTG-INFO-02']
            assert persister.add_payload.call_args_list[0][1]["request"] ==Request("http://perdu.com/")


@pytest.mark.asyncio
@respx.mock
async def test_root_attack_root_url():
    target_url = "http://perdu.com/"

    respx.get(target_url).mock(
        return_value=httpx.Response(
            200,
            text="foobar"
        )
    )

    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE") or "/home"
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")
    persister.get_root_url.return_value = "http://perdu.com/"

    request = Request(target_url)
    request.path_id = 1

    static_files = [
        "README.md",
        "index.html"
    ]

    with patch.object(
            ModuleHtp, "_get_static_files", return_value=static_files, autospec=True
    ) as mock_get_static_files, \
            patch.object(
                ModuleHtp, "_analyze_file", autospec=True
            ) as mock_analyze_file, \
            patch.object(
                ModuleHtp, "_init_db", autospec=True
            ) as mock_init_db:
        crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
        async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
            options = {"timeout": 10, "level": 2, "tasks": 20}
            module_htp = ModuleHtp(crawler, persister, options, Event(), crawler_configuration)
            module_htp._root_url = target_url
            target_request = Request(target_url)
            mock_analyze_file.return_value = None

            await module_htp.attack(target_request)

            mock_get_static_files.assert_called_once()
            mock_init_db.assert_called_once()
            assert mock_analyze_file.call_count == 3


@pytest.mark.asyncio
@respx.mock
async def test_attack():
    target_url = "http://perdu.com/"

    respx.get(target_url).mock(
        return_value=httpx.Response(
            200,
            text="foobar"
        )
    )

    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE") or "/home"
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")
    persister.get_root_url.return_value = "http://perdu.com/"

    request = Request(target_url)
    request.path_id = 1

    static_files = [
        "README.md",
        "index.html"
    ]

    future_init_db = asyncio.Future()
    future_init_db.set_result(None)

    with patch.object(
            ModuleHtp, "_get_static_files", return_value=static_files, autospec=True
    ) as mock_get_static_files, \
            patch.object(
                ModuleHtp, "_analyze_file", autospec=True
            ) as mock_analyze_file, \
            patch.object(ModuleHtp, "_init_db", return_value=future_init_db):
        crawler_configuration = CrawlerConfiguration(Request(target_url))
        async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
            options = {"timeout": 10, "level": 2, "tasks": 20}
            module_htp = ModuleHtp(crawler, persister, options, Event(), crawler_configuration)
            module_htp._root_url = target_url
            target_request = Request(target_url + "index.html")
            options = {"timeout": 10, "level": 2, "tasks": 20}
            mock_analyze_file.return_value = None

            await module_htp.attack(target_request)

            mock_get_static_files.assert_not_called()
            assert mock_analyze_file.call_count == 1


@pytest.mark.parametrize(
    "known_versions, detected_versions, matching_versions",
    [
        [
            ["1.0", "1.1", "1.2", "1.3", "1.3.1"],
            [["1.1", "1.3"], ["1.2", "1.3.1"]],
            ["1.1", "1.2", "1.3", "1.3.1"],
        ],
        [
            ["1.0", "1.1", "1.2", "1.2.1", "1.3", "1.4", "1.5", "1.6"],
            [["1.2", "1.2.1", "1.3"], ["1.3", "1.4"], ["1.5", "1.5"], ["1.0", "1.2"]],
            ["1.0", "1.1", "1.2", "1.2.1", "1.3", "1.4", "1.5"],
        ],
        [
            ["1.0", "1.1", "1.2", "1.2.1", "1.3", "1.3.1"],
            [["0.7", "1.3"], ["1.2", "1.4"]],
            ["1.2", "1.2.1", "1.3"],
        ],
        [
            ["0.8", "1.1", "1.2", "1.2.1", "1.3", "1.3.1"],
            [["0.7", "1.3"], ["1.3.2", "1.4"]],
            ["1.3"],
        ],
        [
            ["1.0", "1.1", "1.2", "1.2.1", "1.3", "1.3.1"],
            [["0.7", "0.8"], ["1.3.2", "1.4"]],
            [],
        ],
    ],
    ids=[
        "regular test #1",
        "regular test #2",
        "missing start end end of range",
        "only one matching version",
        "no matching version",
    ]
)
def test_get_matching_technology_versions(known_versions, detected_versions, matching_versions):
    assert matching_versions == get_matching_versions(known_versions, detected_versions)
