from asyncio import Event

import respx
import httpx
import pytest

from wapitiCore.net.web import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_wp_enum import mod_wp_enum
from wapitiCore.language.vulnerability import _
from tests import AsyncMock


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

    crawler = AsyncCrawler("http://perdu.com/")

    options = {"timeout": 10, "level": 2}

    module = mod_wp_enum(crawler, persister, options, Event())

    await module.attack(request)

    assert not persister.add_payload.call_count
    await crawler.close()


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

    persister = AsyncMock()

    request = Request("http://perdu.com")
    request.path_id = 1

    crawler = AsyncCrawler("http://perdu.com")

    options = {"timeout": 10, "level": 2}

    module = mod_wp_enum(crawler, persister, options, Event())

    await module.attack(request)

    assert persister.add_payload.call_count
    assert persister.add_payload.call_args_list[0][1]["module"] == "wp_enum"
    assert persister.add_payload.call_args_list[0][1]["category"] == _("Fingerprint web technology")
    assert persister.add_payload.call_args_list[0][1]["info"] == (
        '{"name": "bbpress", "versions": ["2.6.6"], "categories": ["WordPress plugins"]}'
    )
    assert persister.add_payload.call_args_list[1][1]["info"] == (
        '{"name": "wp-reset", "versions": [""], "categories": ["WordPress plugins"]}'
    )
    assert persister.add_payload.call_args_list[2][1]["info"] == (
        '{"name": "unyson", "versions": [""], "categories": ["WordPress plugins"]}'
    )
    await crawler.close()


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

    persister = AsyncMock()

    request = Request("http://perdu.com")
    request.path_id = 1

    crawler = AsyncCrawler("http://perdu.com")

    options = {"timeout": 10, "level": 2}

    module = mod_wp_enum(crawler, persister, options, Event())

    await module.attack(request)

    assert persister.add_payload.call_count
    assert persister.add_payload.call_args_list[0][1]["info"] == (
        '{"name": "twentynineteen", "versions": ["1.9"], "categories": ["WordPress themes"]}'
    )
    assert persister.add_payload.call_args_list[1][1]["info"] == (
        '{"name": "seedlet", "versions": [""], "categories": ["WordPress themes"]}'
    )
    assert persister.add_payload.call_args_list[2][1]["info"] == (
        '{"name": "customify", "versions": [""], "categories": ["WordPress themes"]}'
    )

    await crawler.close()
