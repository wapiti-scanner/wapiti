import asyncio
import os
from asyncio import Event
from unittest.mock import patch, MagicMock, PropertyMock, AsyncMock

import httpx
import pytest
import respx

from wapitiCore.attack.mod_htp import ModuleHtp
from wapitiCore.language.language import _
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.net.crawler_configuration import CrawlerConfiguration
from wapitiCore.net import Request


@pytest.mark.asyncio
@respx.mock
async def test_must_attack():
    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE")
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
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE")
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1

    techno = "techno"
    techno_versions = '"{\\"versions\\": [\\"1.2\\", \\"1.2.1\\"]}"'  # '{"versions": ["1.2", "1.2.1"]}'

    with patch.object(ModuleHtp, "_find_technology", return_value=(techno, techno_versions)):
        crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
        async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
            options = {"timeout": 10, "level": 2}
            module_htp = ModuleHtp(crawler, persister, options, Event(), crawler_configuration)

            await module_htp._analyze_file(Request("http://perdu.com/"))

            assert len(module_htp.tech_versions) == 1
            assert module_htp.tech_versions.get(techno) is not None
            assert module_htp.tech_versions.get(techno) == [["1.2", "1.2.1"]]


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
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE")
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1

    with patch.object(ModuleHtp, "_find_technology", return_value=None):
        crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
        async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
            options = {"timeout": 10, "level": 2}
            module_htp = ModuleHtp(crawler, persister, options, Event(), crawler_configuration)

            await module_htp._analyze_file(Request("http://perdu.com"))

            assert len(module_htp.tech_versions) == 0


@pytest.mark.asyncio
@respx.mock
async def test_analyze_file_none_content():
    respx.get("http://perdu.com/").mock(
        return_value=None
    )

    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE")
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}
        module_htp = ModuleHtp(crawler, persister, options, Event(), crawler_configuration)

        await module_htp._analyze_file(Request("http://perdu.com"))

        assert len(module_htp.tech_versions) == 0


@pytest.mark.asyncio
@respx.mock
async def test_analyze_file_request_error():
    respx.get("http://perdu.com/").mock(
        side_effect=httpx.RequestError("error")
    )

    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE")
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}
        module_htp = ModuleHtp(crawler, persister, options, Event(), crawler_configuration)

        await module_htp._analyze_file(Request("http://perdu.com"))

        assert len(module_htp.tech_versions) == 0
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
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE")
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1

    with patch("wapitiCore.attack.mod_htp.ModuleHtp.add_vuln_info", autospec=True) as mock_add_vuln_info, \
            patch.object(ModuleHtp, "_db", new_callable=PropertyMock) as mock_db:
        crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
        async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
            options = {"timeout": 10, "level": 2}
            module_htp = ModuleHtp(crawler, persister, options, Event(), crawler_configuration)

            await module_htp.finish()

            mock_db.assert_called()
            mock_add_vuln_info.assert_not_called()


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
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE")
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")
    persister.get_root_url.return_value = "http://perdu.com/"

    request = Request("http://perdu.com/")
    request.path_id = 1

    techno = "techno"

    versions = ["1.0", "1.1", "1.2", "1.2.1", "1.3", "1.4"]

    async def async_magic():
        pass

    MagicMock.__await__ = lambda x: async_magic().__await__()
    with patch("wapitiCore.attack.mod_htp.ModuleHtp.add_vuln_info", autospec=True) as mock_add_vuln_info, \
            patch.object(ModuleHtp, "_db", new_callable=PropertyMock) as mock_db, \
            patch.object(ModuleHtp, "_get_versions", return_value=versions):
        crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
        async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
            options = {"timeout": 10, "level": 2}
            module_htp = ModuleHtp(crawler, persister, options, Event(), crawler_configuration)
            module_htp._root_url = "http://perdu.com/"

            module_htp.tech_versions[techno] = [["1.2", "1.2.1", "1.3"]]

            await module_htp.finish()

            mock_add_vuln_info.assert_called_once_with(
                module_htp,
                category=_("Fingerprint web server"),
                request=Request("http://perdu.com/"),
                info='{"name": "techno", "versions": ["1.2", "1.2.1", "1.3"]}'
            )


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
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE")
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")
    persister.get_root_url.return_value = "http://perdu.com/"

    request = Request("http://perdu.com/")
    request.path_id = 1

    techno = "techno"

    versions = ["1.0", "1.1", "1.2", "1.2.1", "1.3", "1.4", "1.5", "1.6"]

    async def async_magic():
        pass

    MagicMock.__await__ = lambda x: async_magic().__await__()
    with patch("wapitiCore.attack.mod_htp.ModuleHtp.add_vuln_info", autospec=True) as mock_add_vuln_info, \
            patch.object(ModuleHtp, "_db", new_callable=PropertyMock) as mock_db, \
            patch.object(ModuleHtp, "_get_versions", return_value=versions):
        crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
        async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
            options = {"timeout": 10, "level": 2}
            module_htp = ModuleHtp(crawler, persister, options, Event(), crawler_configuration)
            module_htp._root_url = "http://perdu.com/"

            module_htp.tech_versions[techno] = [["1.2", "1.2.1", "1.3"], ["1.3", "1.4"], ["1.5", "1.5"], ["1.0", "1.2"]]

            await module_htp.finish()

            mock_add_vuln_info.assert_called_once_with(
                module_htp,
                category=_("Fingerprint web server"),
                request=Request("http://perdu.com/"),
                info='{"name": "techno", "versions": ["1.0", "1.1", "1.2", "1.2.1", "1.3", "1.4", "1.5"]}'
            )


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
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE")
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
            options = {"timeout": 10, "level": 2}
            module_htp = ModuleHtp(crawler, persister, options, Event(), crawler_configuration)
            module_htp._root_url = target_url
            target_request = Request(target_url)

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
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE")
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
            options = {"timeout": 10, "level": 2}
            module_htp = ModuleHtp(crawler, persister, options, Event(), crawler_configuration)
            module_htp._root_url = target_url
            target_request = Request(target_url + "index.html")

            await module_htp.attack(target_request)

            mock_get_static_files.assert_not_called()
            assert mock_analyze_file.call_count == 1
