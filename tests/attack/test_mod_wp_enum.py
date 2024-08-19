from asyncio import Event
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from wapitiCore.attack.mod_wp_enum import ModuleWpEnum
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net import Request


@pytest.mark.asyncio
@respx.mock
async def test_no_wordpress():
    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong></body></html>"
        )
    )

    persister = AsyncMock()

    request = Request("http://perdu.com/")
    request.path_id = 1
    # persister.requests.append(request)

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleWpEnum(crawler, persister, options, Event(), crawler_configuration)

        await module.attack(request)

        assert not persister.add_payload.call_count


@pytest.mark.asyncio
@respx.mock
async def test_plugin():
    # Response to tell that Wordpress is used
    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va wordpress vous aider</h2> \
            Wordpress wordpress WordPress\
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong></body></html>"
        )
    )

    # Response for versioned plugin
    respx.get("http://perdu.com/wp-content/plugins/bbpress/readme.txt").mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va wordpress vous aider</h2> \
            Wordpress wordpress WordPress\
            Stable tag: 2.6.6 \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong></body></html>"
        )
    )

    # Response for plugin detected without version (403 forbiden response)
    respx.get("http://perdu.com/wp-content/plugins/wp-reset/readme.txt").mock(
        return_value=httpx.Response(
            403,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va wordpress vous aider</h2> \
            Wordpress wordpress WordPress\
            Stable tag: 9.5.1 \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong></body></html>"
        )
    )

    # Response for bad format readme.txt of plugin
    respx.get("http://perdu.com/wp-content/plugins/unyson/readme.txt").mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va wordpress vous aider</h2> \
            Wordpress wordpress WordPress\
            Version Tested : 4.5 \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong></body></html>"
        )
    )

    respx.get(url__regex=r"http://perdu.com/wp-content/plugins/.*?/readme.txt").mock(return_value=httpx.Response(404))
    respx.get(url__regex=r"http://perdu.com/wp-content/themes/.*?/readme.txt").mock(return_value=httpx.Response(404))
    respx.get(url__regex=r"http://perdu.com/.*?").mock(return_value=httpx.Response(404))

    persister = AsyncMock()

    request = Request("http://perdu.com")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleWpEnum(crawler, persister, options, Event(), crawler_configuration)

        await module.attack(request)

        assert persister.add_payload.call_count

        assert persister.add_payload.call_args_list[0][1]["module"] == "wp_enum"
        assert persister.add_payload.call_args_list[0][1]["category"] == "Fingerprint web technology"
        assert persister.add_payload.call_args_list[0][1]["info"] == (
            '{"name": "WordPress", "versions": [], "categories": ["CMS", "Blogs"], "groups": ["Content"]}'
        )

        assert persister.add_payload.call_args_list[1][1]["module"] == "wp_enum"
        assert persister.add_payload.call_args_list[1][1]["category"] == "Fingerprint web technology"
        assert persister.add_payload.call_args_list[1][1]["info"] == (
            '{"name": "bbpress", "versions": ["2.6.6"], "categories": ["WordPress plugins"], "groups": ["Add-ons"]}'
        )
        assert persister.add_payload.call_args_list[2][1]["info"] == (
            '{"name": "wp-reset", "versions": [""], "categories": ["WordPress plugins"], "groups": ["Add-ons"]}'
        )
        assert persister.add_payload.call_args_list[3][1]["info"] == (
            '{"name": "unyson", "versions": [""], "categories": ["WordPress plugins"], "groups": ["Add-ons"]}'
        )


@pytest.mark.asyncio
@respx.mock
async def test_theme():
    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va wordpress vous aider</h2> \
            Wordpress wordpress WordPress\
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong></body></html>"
        )
    )

    # Response for versioned theme
    respx.get("http://perdu.com/wp-content/themes/twentynineteen/readme.txt").mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va wordpress vous aider</h2> \
            Wordpress wordpress WordPress\
            Stable tag: 1.9 \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong></body></html>"
        )
    )

    # Response for theme detected without version (403 forbidden response)
    respx.get("http://perdu.com/wp-content/themes/seedlet/readme.txt").mock(
        return_value=httpx.Response(
            403,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va wordpress vous aider</h2> \
            Wordpress wordpress WordPress\
            Stable tag: 5.4 \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong></body></html>"
        )
    )

    # Response for bad format readme.txt of theme
    respx.get("http://perdu.com/wp-content/themes/customify/readme.txt").mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va wordpress vous aider</h2> \
            Wordpress wordpress WordPress\
            Version Tested : 3.2 \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong></body></html>"
        )
    )

    respx.get(url__regex=r"http://perdu.com/wp-content/plugins/.*?/readme.txt").mock(return_value=httpx.Response(404))
    respx.get(url__regex=r"http://perdu.com/wp-content/themes/.*?/readme.txt").mock(return_value=httpx.Response(404))
    respx.get(url__regex=r"http://perdu.com/.*?").mock(return_value=httpx.Response(404))

    persister = AsyncMock()

    request = Request("http://perdu.com")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleWpEnum(crawler, persister, options, Event(), crawler_configuration)

        await module.attack(request)

        assert persister.add_payload.call_count
        assert persister.add_payload.call_args_list[1][1]["info"] == (
            '{"name": "twentynineteen", "versions": ["1.9"], "categories": ["WordPress themes"], "groups": ["Add-ons"]}'
        )
        assert persister.add_payload.call_args_list[2][1]["info"] == (
            '{"name": "seedlet", "versions": [""], "categories": ["WordPress themes"], "groups": ["Add-ons"]}'
        )
        assert persister.add_payload.call_args_list[3][1]["info"] == (
            '{"name": "customify", "versions": [""], "categories": ["WordPress themes"], "groups": ["Add-ons"]}'
        )


@pytest.mark.asyncio
@respx.mock
async def test_wp_version():
    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va wordpress vous aider</h2> \
            Wordpress wordpress WordPress\
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong></body></html>"
        )
    )

    # test with no content-type, should be skipped
    respx.get("http://perdu.com/feed/").mock(
        return_value=httpx.Response(
            200,
            text='<?xml version="1.0" encoding="UTF-8"?>\
                <rss version="2.0">\
                    <channel>\
                        <generator>https://wordpress.org/?v=4.3.2</generator>\
                    </channel>\
                </rss>'
        )
    )

    # test with content-type different from XML, should be skipped
    respx.get("http://perdu.com/comments/feed/").mock(
        return_value=httpx.Response(
            200,
            text='<?xml version="1.0" encoding="UTF-8"?>\
                <rss version="2.0">\
                    <channel>\
                        <generator>https://wordpress.org/?v=5.4.3</generator>\
                    </channel>\
                </rss>',
            headers={"content-type":"text/html, charset=UTF-8"}
        )
    )

    respx.get("http://perdu.com/feed/rss/").mock(
        return_value=httpx.Response(
            200,
            text='<?xml version="1.0" encoding="UTF-8"?>\
                <rss version="2.0">\
                    <channel>\
                        <generator>https://wordpress.org/?v=5.8.2</generator>\
                    </channel>\
                </rss>',
            headers={"content-type":"application/rss+xml, charset=UTF-8"}
        )
    )

    respx.get(url__regex=r"http://perdu.com/wp-content/plugins/.*?/readme.txt").mock(return_value=httpx.Response(404))
    respx.get(url__regex=r"http://perdu.com/wp-content/themes/.*?/readme.txt").mock(return_value=httpx.Response(404))

    persister = AsyncMock()

    request = Request("http://perdu.com")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        with patch.object(ModuleWpEnum, "detect_plugin", AsyncMock()) as mock_detect_plugin, \
                patch.object(ModuleWpEnum, "detect_theme", AsyncMock()) as mock_detect_theme:
            module = ModuleWpEnum(crawler, persister, options, Event(), crawler_configuration)

            await module.attack(request)

            mock_detect_plugin.assert_called_once()
            mock_detect_theme.assert_called_once()
            assert persister.add_payload.call_count == 2
            assert persister.add_payload.call_args_list[0][1]["info"] == (
                '{"name": "WordPress", "versions": ["5.8.2"], "categories": ["CMS", "Blogs"], "groups": ["Content"]}'
            )
            assert persister.add_payload.call_args_list[1][1]["info"] == (
                '{"name": "WordPress", "versions": ["5.8.2"], "categories": ["CMS", "Blogs"], "groups": ["Content"]}'
            )


@pytest.mark.asyncio
@respx.mock
async def test_wp_version_no_file():
    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va wordpress vous aider</h2> \
            Wordpress wordpress WordPress\
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong></body></html>"
        )
    )

    respx.get(url__regex=r"http://perdu.com/.*?").mock(return_value=httpx.Response(404))

    persister = AsyncMock()

    request = Request("http://perdu.com")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        with patch.object(ModuleWpEnum, "detect_plugin", AsyncMock()) as mock_detect_plugin, \
                patch.object(ModuleWpEnum, "detect_theme", AsyncMock()) as mock_detect_theme:
            module = ModuleWpEnum(crawler, persister, options, Event(), crawler_configuration)

            await module.attack(request)

            mock_detect_plugin.assert_called_once()
            mock_detect_theme.assert_called_once()
            assert persister.add_payload.call_count == 1
