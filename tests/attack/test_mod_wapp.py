from unittest.mock import Mock

import os
import responses

from wapitiCore.net.web import Request
from wapitiCore.net.crawler import Crawler
from wapitiCore.attack.mod_wapp import mod_wapp


class FakePersister:

    CONFIG_DIR_NAME = "config"
    HOME_DIR = os.getenv("HOME") or os.getenv("USERPROFILE")
    BASE_DIR = os.path.join(HOME_DIR, ".wapiti")
    CONFIG_DIR = os.path.join(BASE_DIR, CONFIG_DIR_NAME)

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

    def add_vulnerability(self, _request_id, _category, _level, _request, parameter, _info):
        self.vulnerabilities.add(parameter)

    def get_root_url(self):
        return self.requests[0].url


@responses.activate
def test_false_positive():
    # Test for false positive
    responses.add_passthru("https://raw.githubusercontent.com/wapiti-scanner/wappalyzer/master/src/technologies.json")

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
    persister.requests.append(request)

    crawler = Crawler("http://perdu.com/")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_wapp(crawler, persister, logger, options)
    module.verbose = 2

    for __ in module.attack():
        pass

    assert not persister.additionals


@responses.activate
def test_url_detection():
    # Test if application is detected using its url regex
    responses.add(
        responses.GET,
        url="http://perdu.com/owa/auth/logon.aspx",
        body="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
        <h2>Pas de panique, on va vous aider</h2> \
        <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong></body></html>"
    )

    persister = FakePersister()

    request = Request("http://perdu.com/owa/auth/logon.aspx")
    request.path_id = 1
    persister.requests.append(request)

    crawler = Crawler("http://perdu.com/")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_wapp(crawler, persister, logger, options)
    module.verbose = 2

    for __ in module.attack():
        pass

    assert persister.additionals
    assert persister.additionals[2] == '{"versions": [], "name": "Outlook Web App", "categories": ["Webmail"]}'


@responses.activate
def test_html_detection():
    # Test if application is detected using its html regex
    responses.add(
        responses.GET,
        url="http://perdu.com/",
        body="<html><head><title>FishEye 2.8.4</title> \
        </head><body><h1>Perdu sur l'Internet ?</h1> \
        <h2>Pas de panique, on va vous aider</h2> \
        </body></html>"
    )

    persister = FakePersister()

    request = Request("http://perdu.com/")
    request.path_id = 1
    persister.requests.append(request)

    crawler = Crawler("http://perdu.com/")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_wapp(crawler, persister, logger, options)
    module.verbose = 2

    for __ in module.attack():
        pass

    assert persister.additionals
    assert persister.additionals[0] == '{"versions": ["2.8.4"], "name": "Atlassian FishEye", "categories": ["Development"]}'


@responses.activate
def test_script_detection():
    # Test if application is detected using its script regex
    responses.add(
        responses.GET,
        url="http://perdu.com/",
        body="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
        <h2>Pas de panique, on va vous aider</h2> \
        <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong> \
        <script src=\"http://chartjs.org/dist/1.4.2/Chart.js\"></script>\
        </body></html>"
    )

    persister = FakePersister()

    request = Request("http://perdu.com/")
    request.path_id = 1
    persister.requests.append(request)

    crawler = Crawler("http://perdu.com/")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_wapp(crawler, persister, logger, options)
    module.verbose = 2

    for __ in module.attack():
        pass

    assert persister.additionals
    assert persister.additionals[0] == '{"versions": ["1.4.2"], "name": "Chart.js", "categories": ["JavaScript graphics"]}'


@responses.activate
def test_cookies_detection():
    # Test if application is detected using its cookies regex
    responses.add(
        responses.GET,
        url="http://perdu.com/",
        body="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
        <h2>Pas de panique, on va vous aider</h2> \
        <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong> \
        </body></html>",
        headers={"Set-Cookie": "ci_csrf_token=4.1"}
    )

    persister = FakePersister()

    request = Request("http://perdu.com/")
    request.path_id = 1
    persister.requests.append(request)

    crawler = Crawler("http://perdu.com/")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_wapp(crawler, persister, logger, options)
    module.verbose = 2

    for __ in module.attack():
        pass

    assert persister.additionals
    assert persister.additionals[0] == '{"versions": ["2+"], "name": "CodeIgniter", "categories": ["Web frameworks"]}'


@responses.activate
def test_headers_detection():
    # Test if application is detected using its headers regex
    responses.add(
        responses.GET,
        url="http://perdu.com/",
        body="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
        <h2>Pas de panique, on va vous aider</h2> \
        <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong> \
        </body></html>",
        headers={"Server": "Cherokee/1.3.4"}
    )

    persister = FakePersister()

    request = Request("http://perdu.com/")
    request.path_id = 1
    persister.requests.append(request)

    crawler = Crawler("http://perdu.com/")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_wapp(crawler, persister, logger, options)
    module.verbose = 2

    for __ in module.attack():
        pass

    assert persister.additionals
    assert persister.additionals[0] == '{"versions": ["1.3.4"], "name": "Cherokee", "categories": ["Web servers"]}'


@responses.activate
def test_meta_detection():
    # Test if application is detected using its meta regex
    responses.add(
        responses.GET,
        url="http://perdu.com/",
        body="<html><head><title>Vous Etes Perdu ?</title> \
        <meta name=\"generator\" content=\"Planet/1.6.2\">    \
        </head><body><h1>Perdu sur l'Internet ?</h1> \
        <h2>Pas de panique, on va vous aider</h2> \
        <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong> \
        </body></html>"
    )

    persister = FakePersister()

    request = Request("http://perdu.com/")
    request.path_id = 1
    persister.requests.append(request)

    crawler = Crawler("http://perdu.com/")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_wapp(crawler, persister, logger, options)
    module.verbose = 2

    for __ in module.attack():
        pass

    assert persister.additionals
    assert persister.additionals[0] == '{"versions": ["1.6.2"], "name": "Planet", "categories": ["Feed readers"]}'


@responses.activate
def test_implies_detection():
    # Test for implied applications
    responses.add(
        responses.GET,
        url="http://perdu.com/",
        body="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
        <h2>Pas de panique, on va vous aider</h2> \
        <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong> \
        </body></html>",
        headers={"X-Generator": "Backdrop CMS 4.5"}
    )

    persister = FakePersister()

    request = Request("http://perdu.com")
    request.path_id = 1
    persister.requests.append(request)

    crawler = Crawler("http://perdu.com")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_wapp(crawler, persister, logger, options)
    module.verbose = 2

    for __ in module.attack():
        pass

    assert persister.additionals
    assert '{"versions": ["4.5"], "name": "Backdrop", "categories": ["CMS"]}' == persister.additionals[0]
    assert '{"versions": [], "name": "PHP", "categories": ["Programming languages"]}' == persister.additionals[1]
