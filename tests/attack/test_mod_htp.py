import asyncio
import os
from asyncio import Event
from unittest import mock
from unittest.mock import MagicMock

import httpx
import pytest
import respx
from hashtheplanet.core.hashtheplanet import HashThePlanet
from tests import AsyncMock
from wapitiCore.attack.mod_htp import ModuleHtp
from wapitiCore.language.language import _
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.net.web import Request


@pytest.mark.asyncio
@respx.mock
async def test_must_attack():
    persister = AsyncMock()
    home_dir = os.getenv("HOME") or os.getenv("USERPROFILE")
    base_dir = os.path.join(home_dir, ".wapiti")
    persister.CONFIG_DIR = os.path.join(base_dir, "config")

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler = AsyncCrawler("http://perdu.com/")
    options = {"timeout": 10, "level": 2}
    module_htp = ModuleHtp(crawler, persister, options, Event())

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
    techno_versions = '{"versions": ["1.2", "1.2.1"]}'

    with mock.patch.object(HashThePlanet, "analyze_str", return_value=(techno, techno_versions)):
        crawler = AsyncCrawler("http://perdu.com/")
        options = {"timeout": 10, "level": 2}
        module_htp = ModuleHtp(crawler, persister, options, Event())

        await module_htp._analyze_file(Request("http://perdu.com"))

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

    with mock.patch.object(HashThePlanet, "analyze_str", return_value=None):
        crawler = AsyncCrawler("http://perdu.com/")
        options = {"timeout": 10, "level": 2}
        module_htp = ModuleHtp(crawler, persister, options, Event())

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


    crawler = AsyncCrawler("http://perdu.com/")
    options = {"timeout": 10, "level": 2}
    module_htp = ModuleHtp(crawler, persister, options, Event())

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

    crawler = AsyncCrawler("http://perdu.com/")
    options = {"timeout": 10, "level": 2}
    module_htp = ModuleHtp(crawler, persister, options, Event())

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

    with mock.patch("wapitiCore.attack.mod_htp.ModuleHtp.add_vuln_info", autospec=True) as mock_add_vuln_info:
        crawler = AsyncCrawler("http://perdu.com/")
        options = {"timeout": 10, "level": 2}
        module_htp = ModuleHtp(crawler, persister, options, Event())

        await module_htp.finish()

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
    techno_versions = '["1.2", "1.2.1", "1.3"]'

    versions = ["1.0", "1.1", "1.2", "1.2.1", "1.3", "1.4"]

    async def async_magic():
        pass
    MagicMock.__await__ = lambda x: async_magic().__await__()
    with mock.patch("wapitiCore.attack.mod_htp.ModuleHtp.add_vuln_info", autospec=True) as mock_add_vuln_info, \
        mock.patch.object(HashThePlanet, "get_versions", return_value=versions):
        crawler = AsyncCrawler("http://perdu.com/")
        options = {"timeout": 10, "level": 2}
        module_htp = ModuleHtp(crawler, persister, options, Event())
        module_htp._root_url = "http://perdu.com/"
        module_htp._htp.get_versions = MagicMock(return_value=versions)

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
    with mock.patch("wapitiCore.attack.mod_htp.ModuleHtp.add_vuln_info", autospec=True) as mock_add_vuln_info, \
        mock.patch.object(HashThePlanet, "get_versions", return_value=versions):
        crawler = AsyncCrawler("http://perdu.com/")
        options = {"timeout": 10, "level": 2}
        module_htp = ModuleHtp(crawler, persister, options, Event())
        module_htp._root_url = "http://perdu.com/"
        module_htp._htp.get_versions = MagicMock(return_value=versions)

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

    with mock.patch.object(
        HashThePlanet, "get_static_files", return_value=static_files, autospec=True
    ) as mock_get_static_files, \
    mock.patch.object(
        ModuleHtp, "_analyze_file", autospec=True
    ) as mock_analyze_file:
        crawler = AsyncCrawler(target_url)
        options = {"timeout": 10, "level": 2}
        module_htp = ModuleHtp(crawler, persister, options, Event())
        module_htp._root_url = target_url
        target_request = Request(target_url)

        await module_htp.attack(target_request)

        mock_get_static_files.assert_called_once()
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

    with mock.patch.object(
        HashThePlanet, "get_static_files", return_value=static_files, autospec=True
    ) as mock_get_static_files, \
    mock.patch.object(
        ModuleHtp, "_analyze_file", autospec=True
    ) as mock_analyze_file:
        crawler = AsyncCrawler(target_url)
        options = {"timeout": 10, "level": 2}
        module_htp = ModuleHtp(crawler, persister, options, Event())
        module_htp._root_url = target_url
        target_request = Request(target_url + "index.html")

        await module_htp.attack(target_request)

        mock_get_static_files.assert_not_called()
        assert mock_analyze_file.call_count == 1
