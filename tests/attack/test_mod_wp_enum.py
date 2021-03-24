from unittest.mock import Mock
import re
import responses

from wapitiCore.net.web import Request
from wapitiCore.net.crawler import Crawler
from wapitiCore.attack.mod_wp_enum import mod_wp_enum


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

@responses.activate
def test_no_wordpress():

    responses.add(
        responses.GET,
        url="http://perdu.com/",
        body="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
        <h2>Pas de panique, on va vous aider</h2> \
        <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong></body></html>"   
    )

    persister = FakePersister()

    request = Request("http://perdu.com/")
    request.path_id = 1
    #persister.requests.append(request)

    crawler = Crawler("http://perdu.com/")

    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_wp_enum(crawler, persister, logger, options)
    module.verbose = 2

    module.attack(request)

    assert not persister.additionals

@responses.activate
def test_plugin():

    #Response to tell that Wordpress is used
    responses.add(
        responses.GET,
        url="http://perdu.com/",
        body="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
        <h2>Pas de panique, on va wordpress vous aider</h2> \
        Wordpress wordpress WordPress\
        <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong></body></html>"   
    )
    #Response for versioned plugin
    responses.add(
        responses.GET,
        url="http://perdu.com/wp-content/plugins/bbpress/readme.txt",
        body="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
        <h2>Pas de panique, on va wordpress vous aider</h2> \
        Wordpress wordpress WordPress\
        Stable tag: 2.6.6 \
        <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong></body></html>"
    )

    #Response for plugin detected without version (403 forbiden response)
    responses.add(
        responses.GET,
        url="http://perdu.com/wp-content/plugins/wp-reset/readme.txt",
        body="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
        <h2>Pas de panique, on va wordpress vous aider</h2> \
        Wordpress wordpress WordPress\
        Stable tag: 9.5.1 \
        <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong></body></html>",
        status=403
    )

    #Response for bad format readme.txt of plugin
    responses.add(
        responses.GET,
        url="http://perdu.com/wp-content/plugins/unyson/readme.txt",
        body="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
        <h2>Pas de panique, on va wordpress vous aider</h2> \
        Wordpress wordpress WordPress\
        Version Tested : 4.5 \
        <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong></body></html>"
    )

    responses.add(
        responses.GET,
        url=re.compile(r"http://perdu.com/wp-content/plugins/.*?/readme.txt"),
        status=404
    )
    responses.add(
        responses.GET,
        url=re.compile(r"http://perdu.com/wp-content/themes/.*?/readme.txt"),
        status=404
    )

    persister = FakePersister()

    request = Request("http://perdu.com")
    request.path_id = 1

    crawler = Crawler("http://perdu.com")

    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_wp_enum(crawler, persister, logger, options)
    module.verbose = 2

    module.attack(request)

    assert persister.additionals
    assert persister.additionals[0] == '{"name": "bbpress", "versions": ["2.6.6"], "categories": ["WordPress plugins"]}'
    assert persister.additionals[1] == '{"name": "wp-reset", "versions": [""], "categories": ["WordPress plugins"]}'
    assert persister.additionals[2] == '{"name": "unyson", "versions": [""], "categories": ["WordPress plugins"]}'

@responses.activate
def test_theme():

    responses.add(
        responses.GET,
        url="http://perdu.com/",
        body="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
        <h2>Pas de panique, on va wordpress vous aider</h2> \
        Wordpress wordpress WordPress\
        <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong></body></html>"   
    )

    #Response for versioned theme
    responses.add(
        responses.GET,
        url="http://perdu.com/wp-content/themes/twentynineteen/readme.txt",
        body="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
        <h2>Pas de panique, on va wordpress vous aider</h2> \
        Wordpress wordpress WordPress\
        Stable tag: 1.9 \
        <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong></body></html>"
    )

    #Response for theme detected without version (403 forbiden response)
    responses.add(
        responses.GET,
        url="http://perdu.com/wp-content/themes/seedlet/readme.txt",
        body="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
        <h2>Pas de panique, on va wordpress vous aider</h2> \
        Wordpress wordpress WordPress\
        Stable tag: 5.4 \
        <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong></body></html>",
        status=403
    )

    #Response for bad format readme.txt of theme
    responses.add(
        responses.GET,
        url="http://perdu.com/wp-content/themes/customify/readme.txt",
        body="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
        <h2>Pas de panique, on va wordpress vous aider</h2> \
        Wordpress wordpress WordPress\
        Version Tested : 3.2 \
        <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong></body></html>"
    )

    responses.add(
        responses.GET,
        url=re.compile(r"http://perdu.com/wp-content/plugins/.*?/readme.txt"),
        status=404
    )
    responses.add(
        responses.GET,
        url=re.compile(r"http://perdu.com/wp-content/themes/.*?/readme.txt"),
        status=404
    )

    persister = FakePersister()

    request = Request("http://perdu.com")
    request.path_id = 1

    crawler = Crawler("http://perdu.com")

    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_wp_enum(crawler, persister, logger, options)
    module.verbose = 2

    module.attack(request)

    assert persister.additionals
    assert persister.additionals[0] == '{"name": "twentynineteen", "versions": ["1.9"], "categories": ["WordPress themes"]}'
    assert persister.additionals[1] == '{"name": "seedlet", "versions": [""], "categories": ["WordPress themes"]}'
    assert persister.additionals[2] == '{"name": "customify", "versions": [""], "categories": ["WordPress themes"]}'
