from unittest.mock import Mock
import os
from asyncio import Event

import httpx
import respx
import pytest

from tests.attack.fake_persister import FakePersister
from wapitiCore.net.web import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_wapp import mod_wapp
from wapitiCore.language.vulnerability import _

@pytest.mark.asyncio
@respx.mock
async def test_false_positive():
    # Test for false positive
    respx.route(host="raw.githubusercontent.com").pass_through()

    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong></body></html>"
        )
    )

    persister = FakePersister()

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler = AsyncCrawler("http://perdu.com/")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_wapp(crawler, persister, logger, options, Event())
    module.verbose = 2

    await module.attack(request)

    assert not persister.additionals
    await crawler.close()


@pytest.mark.asyncio
@respx.mock
async def test_url_detection():
    # Test if application is detected using its url regex
    respx.get("http://perdu.com/owa/auth/logon.aspx").mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong></body></html>"
        )
    )

    persister = FakePersister()

    request = Request("http://perdu.com/owa/auth/logon.aspx")
    request.path_id = 1

    crawler = AsyncCrawler("http://perdu.com/")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_wapp(crawler, persister, logger, options, Event())
    module.verbose = 2

    await module.attack(request)

    assert persister.module == "wapp"
    assert persister.additionals
    assert persister.additionals[2]["category"] == _("Fingerprint web technology")
    assert persister.additionals[2]["info"] == '{"versions": [], "name": "Outlook Web App", "categories": ["Webmail"]}'
    await crawler.close()


@pytest.mark.asyncio
@respx.mock
async def test_html_detection():
    # Test if application is detected using its html regex
    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>FishEye 2.8.4</title> \
            </head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            </body></html>"
        )
    )

    persister = FakePersister()

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler = AsyncCrawler("http://perdu.com/")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_wapp(crawler, persister, logger, options, Event())
    module.verbose = 2

    await module.attack(request)

    assert persister.additionals
    assert persister.additionals[0]["info"] == \
           '{"versions": ["2.8.4"], "name": "Atlassian FishEye", "categories": ["Development"]}'
    await crawler.close()


@pytest.mark.asyncio
@respx.mock
async def test_script_detection():
    # Test if application is detected using its script regex
    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong> \
            <script src=\"http://chartjs.org/dist/1.4.2/Chart.js\"></script>\
            </body></html>"
        )
    )

    persister = FakePersister()

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler = AsyncCrawler("http://perdu.com/")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_wapp(crawler, persister, logger, options, Event())
    module.verbose = 2

    await module.attack(request)

    assert persister.additionals
    assert persister.additionals[0]["info"] == \
           '{"versions": ["1.4.2"], "name": "Chart.js", "categories": ["JavaScript graphics"]}'
    await crawler.close()


@pytest.mark.asyncio
@respx.mock
async def test_cookies_detection():
    # Test if application is detected using its cookies regex
    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong> \
            </body></html>",
            headers={"Set-Cookie": "ci_csrf_token=4.1"}
        )
    )

    persister = FakePersister()

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler = AsyncCrawler("http://perdu.com/")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_wapp(crawler, persister, logger, options, Event())
    module.verbose = 2

    await module.attack(request)

    assert persister.additionals
    assert persister.additionals[0]["info"] == \
        '{"versions": ["2+"], "name": "CodeIgniter", "categories": ["Web frameworks"]}'
    await crawler.close()


@pytest.mark.asyncio
@respx.mock
async def test_headers_detection():
    # Test if application is detected using its headers regex
    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
                    <h2>Pas de panique, on va vous aider</h2> \
                    <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong> \
                    </body></html>",
            headers={"Server": "Cherokee/1.3.4"}
        )
    )

    persister = FakePersister()

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler = AsyncCrawler("http://perdu.com/")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_wapp(crawler, persister, logger, options, Event())
    module.verbose = 2

    await module.attack(request)

    assert persister.additionals
    assert persister.additionals[0]["info"] == \
        '{"versions": ["1.3.4"], "name": "Cherokee", "categories": ["Web servers"]}'
    await crawler.close()


@pytest.mark.asyncio
@respx.mock
async def test_meta_detection():
    # Test if application is detected using its meta regex
    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title> \
            <meta name=\"generator\" content=\"Planet/1.6.2\">    \
            </head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong> \
            </body></html>"
        )
    )

    persister = FakePersister()

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler = AsyncCrawler("http://perdu.com/")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_wapp(crawler, persister, logger, options, Event())
    module.verbose = 2

    await module.attack(request)

    assert persister.additionals
    assert persister.additionals[0]["info"] == \
        '{"versions": ["1.6.2"], "name": "Planet", "categories": ["Feed readers"]}'
    await crawler.close()


@pytest.mark.asyncio
@respx.mock
async def test_multi_detection():
    # Test if application is detected using several ways
    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title> \
            <meta name=\"generator\" content=\"WordPress 5.6.1\">    \
            </head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong> \
            <script type=\"text/javascript\" src=\"https://perdu.com/wp-includes/js/wp-embed.min.js\" ></script> \
            </body></html>",
            headers={"link": "<http://perdu.com/wp-json/>; rel=\"https://api.w.org/\""}
        )
    )

    persister = FakePersister()

    request = Request("http://perdu.com/")
    request.path_id = 1

    crawler = AsyncCrawler("http://perdu.com/")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_wapp(crawler, persister, logger, options, Event())
    module.verbose = 2

    await module.attack(request)

    assert persister.additionals
    assert persister.additionals[-1]["info"] == \
        '{"versions": ["5.6.1"], "name": "WordPress", "categories": ["CMS", "Blogs"]}'
    await crawler.close()


@pytest.mark.asyncio
@respx.mock
async def test_implies_detection():
    # Test for implied applications
    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong> \
            </body></html>",
            headers={"X-Generator": "Backdrop CMS 4.5"}
        )
    )

    persister = FakePersister()

    request = Request("http://perdu.com")
    request.path_id = 1

    crawler = AsyncCrawler("http://perdu.com")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_wapp(crawler, persister, logger, options, Event())
    module.verbose = 2

    await module.attack(request)

    assert persister.additionals
    assert persister.additionals[0]["info"] == '{"versions": ["4.5"], "name": "Backdrop", "categories": ["CMS"]}'
    assert persister.additionals[1]["info"] == \
        '{"versions": [], "name": "PHP", "categories": ["Programming languages"]}'
    await crawler.close()


@pytest.mark.asyncio
@respx.mock
async def test_vulnerabilities():
    # Test for vulnerabilities detected
    respx.get("http://perdu.com/").mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong> \
            </body></html>",
            headers={"X-Generator": "Backdrop CMS 4.5", "Server": "Cherokee/1.3.4"}
        )
    )

    persister = FakePersister()

    request = Request("http://perdu.com")
    request.path_id = 1

    crawler = AsyncCrawler("http://perdu.com")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_wapp(crawler, persister, logger, options, Event())
    module.verbose = 2

    await module.attack(request)

    assert persister.vulnerabilities
    assert persister.vulnerabilities[0]["info"] == '{"versions": ["4.5"], "name": "Backdrop", "categories": ["CMS"]}'
    assert persister.vulnerabilities[0]["category"] == _("Fingerprint web application framework")
    assert persister.vulnerabilities[1]["info"] == \
           '{"versions": ["1.3.4"], "name": "Cherokee", "categories": ["Web servers"]}'
    assert persister.vulnerabilities[1]["category"] == _("Fingerprint web server")
    await crawler.close()
