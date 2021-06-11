from unittest.mock import Mock
import os
import sys
from os.path import join as path_join
from asyncio import Event

import httpx
import respx
import pytest

from tests.attack.fake_persister import FakePersister
from wapitiCore.net.web import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_drupal_enum import mod_drupal_enum
from wapitiCore.language.vulnerability import _

# Test no Drupal detected
@pytest.mark.asyncio
@respx.mock
async def test_no_drupal():
    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong></body></html>"
        )
    )

    respx.get(url__regex=r"http://perdu.com/.*?").mock(return_value=httpx.Response(404))

    persister = FakePersister()

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler = AsyncCrawler("http://perdu.com/")

    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_drupal_enum(crawler, persister, logger, options, Event())
    module.verbose = 2

    await module.attack(request)

    assert not persister.additionals
    await crawler.close()


@pytest.mark.asyncio
@respx.mock
async def test_version_detected():

    base_dir = os.path.dirname(sys.modules["wapitiCore"].__file__)
    test_directory = os.path.join(base_dir, "..", "tests/data/drupal/")
    changelog_file = "CHANGELOG.txt"

    with open(path_join(test_directory, changelog_file), errors="ignore") as changelog:
        data = changelog.read()

    # Response to tell that Drupal is used
    respx.get("http://perdu.com/sites/").mock(return_value=httpx.Response(403))

    # Response for changelog.txt
    respx.get("http://perdu.com/CHANGELOG.txt").mock(return_value=httpx.Response(200, text=data))

    respx.get(url__regex=r"http://perdu.com/.*?").mock(return_value=httpx.Response(404))

    persister = FakePersister()

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler = AsyncCrawler("http://perdu.com/")

    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_drupal_enum(crawler, persister, logger, options, Event())
    module.verbose = 2

    await module.attack(request)

    assert persister.module == "drupal_enum"
    assert persister.additionals
    assert persister.additionals[0]["category"] == _("Fingerprint web technology")
    assert persister.additionals[0]["info"] == '{"name": "Drupal", "versions": ["7.67"], "categories": ["CMS Drupal"]}'
    await crawler.close()


@pytest.mark.asyncio
@respx.mock
async def test_multi_versions_detected():

    base_dir = os.path.dirname(sys.modules["wapitiCore"].__file__)
    test_directory = os.path.join(base_dir, "..", "tests/data/drupal/")
    maintainers_file = "MAINTAINERS.txt"

    with open(path_join(test_directory, maintainers_file), errors="ignore") as maintainers:
        data = maintainers.read()

    # Response to tell that Drupal is used
    respx.get("http://perdu.com/sites/").mock(return_value=httpx.Response(403))

    # Response for  maintainers.txt
    respx.get("http://perdu.com/core/MAINTAINERS.txt").mock(return_value=httpx.Response(200, text=data))

    respx.get(url__regex=r"http://perdu.com/.*?").mock(return_value=httpx.Response(404))

    persister = FakePersister()

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler = AsyncCrawler("http://perdu.com/")

    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_drupal_enum(crawler, persister, logger, options, Event())
    module.verbose = 2

    await module.attack(request)

    assert persister.additionals
    assert persister.additionals[0]["info"] == \
        '{"name": "Drupal", "versions": ["8.0.0-beta4", "8.0.0-beta5", "8.0.0-beta6"], "categories": ["CMS Drupal"]}'
    await crawler.close()


@pytest.mark.asyncio
@respx.mock
async def test_version_not_detected():

    base_dir = os.path.dirname(sys.modules["wapitiCore"].__file__)
    test_directory = os.path.join(base_dir, "..", "tests/data/drupal/")
    changelog_edited = "CHANGELOG_EDITED.txt"

    with open(path_join(test_directory, changelog_edited), errors="ignore") as changelog:
        data = changelog.read()

    # Response to tell that Drupal is used
    respx.get("http://perdu.com/sites/").mock(return_value=httpx.Response(403))

    # Response for edited changelog.txt
    respx.get("http://perdu.com/CHANGELOG.txt").mock(return_value=httpx.Response(200, text=data))

    respx.get(url__regex=r"http://perdu.com/.*?").mock(return_value=httpx.Response(404))

    persister = FakePersister()

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler = AsyncCrawler("http://perdu.com/")

    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_drupal_enum(crawler, persister, logger, options, Event())
    module.verbose = 2

    await module.attack(request)

    assert persister.additionals
    assert persister.additionals[0]["info"] == '{"name": "Drupal", "versions": [""], "categories": ["CMS Drupal"]}'
    await crawler.close()
