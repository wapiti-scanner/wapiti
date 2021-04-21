from unittest.mock import Mock
import re
import os
import sys
from os.path import join as path_join
from asyncio import Event

import responses
import pytest

from wapitiCore.net.web import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_drupal_enum import mod_drupal_enum


class FakePersister:

    def __init__(self):
        self.requests = []
        self.additionals = []
        self.anomalies = set()
        self.vulnerabilities = set()

    def get_links(self, _path, _attack_module):
        return self.requests

    def add_additional(self, request_id: int = -1, category=None, level=0, request=None, parameter="", info=""):
        self.additionals.append(info)

    def add_anomaly(self, _request_id, _category, _level, _request, parameter, _info):
        self.anomalies.add(parameter)

    def add_vulnerability(self, request_id: int = -1, category=None, level=0, request=None, parameter="", info=""):
        self.vulnerabilities.add(parameter)

    def get_root_url(self):
        return self.requests[0].url


# Test no Drupal detected
@pytest.mark.asyncio
@responses.activate
async def test_no_drupal():

    responses.add(
        responses.GET,
        url="http://perdu.com/",
        body="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
        <h2>Pas de panique, on va vous aider</h2> \
        <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong></body></html>"   
    )

    responses.add(
        responses.GET,
        url=re.compile(r"http://perdu.com/.*?"),
        status=404
    )

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


@pytest.mark.asyncio
@responses.activate
async def test_version_detected():

    base_dir = os.path.dirname(sys.modules["wapitiCore"].__file__)
    test_directory = os.path.join(base_dir, "..", "tests/data/drupal/")
    changelog_file = "CHANGELOG.txt"

    with open(path_join(test_directory, changelog_file), errors="ignore") as changelog:
        data = changelog.read()

    # Response to tell that Drupal is used
    responses.add(
        responses.GET,
        url="http://perdu.com/sites/",
        status=403
    )
    # Response for changelog.txt
    responses.add(
        responses.GET,
        url="http://perdu.com/CHANGELOG.txt",
        body=data
    )

    responses.add(
        responses.GET,
        url=re.compile(r"http://perdu.com/.*?"),
        status=404
    )

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
    assert persister.additionals[0] == '{"name": "Drupal", "versions": ["7.67"], "categories": ["CMS Drupal"]}'


@pytest.mark.asyncio
@responses.activate
async def test_multi_versions_detected():

    base_dir = os.path.dirname(sys.modules["wapitiCore"].__file__)
    test_directory = os.path.join(base_dir, "..", "tests/data/drupal/")
    maintainers_file = "MAINTAINERS.txt"

    with open(path_join(test_directory, maintainers_file), errors="ignore") as maintainers:
        data = maintainers.read()

    # Response to tell that Drupal is used
    responses.add(
        responses.GET,
        url="http://perdu.com/sites/",
        status=403
    )
    # Response for  maintainers.txt
    responses.add(
        responses.GET,
        url="http://perdu.com/core/MAINTAINERS.txt",
        body=data
    )

    responses.add(
        responses.GET,
        url=re.compile(r"http://perdu.com/.*?"),
        status=404
    )

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
    assert persister.additionals[0] == '{"name": "Drupal", "versions": ["8.0.0-beta4", "8.0.0-beta5", "8.0.0-beta6"], "categories": ["CMS Drupal"]}'


@pytest.mark.asyncio
@responses.activate
async def test_version_not_detected():

    base_dir = os.path.dirname(sys.modules["wapitiCore"].__file__)
    test_directory = os.path.join(base_dir, "..", "tests/data/drupal/")
    changelog_edited = "CHANGELOG_EDITED.txt"

    with open(path_join(test_directory, changelog_edited), errors="ignore") as changelog:
        data = changelog.read()

    # Response to tell that Drupal is used
    responses.add(
        responses.GET,
        url="http://perdu.com/sites/",
        status=403
    )
    # Response for edited changelog.txt
    responses.add(
        responses.GET,
        url="http://perdu.com/CHANGELOG.txt",
        body=data
    )

    responses.add(
        responses.GET,
        url=re.compile(r"http://perdu.com/.*?"),
        status=404
    )

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
    assert persister.additionals[0] == '{"name": "Drupal", "versions": [""], "categories": ["CMS Drupal"]}'
