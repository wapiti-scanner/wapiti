from subprocess import Popen
import os
import sys
from time import sleep
from asyncio import Event, sleep as Sleep
from unittest.mock import AsyncMock

import httpx
import pytest

from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_file import ModuleFile, has_prefix_or_suffix, find_warning_message, FileWarning


@pytest.fixture(autouse=True)
def run_around_tests():
    base_dir = os.path.dirname(sys.modules["wapitiCore"].__file__)
    test_directory = os.path.join(base_dir, "..", "tests/data/")

    proc = Popen(["php", "-S", "127.0.0.1:65085", "-a", "-t", test_directory])
    sleep(.5)
    yield
    proc.terminate()


@pytest.mark.asyncio
async def test_inclusion_detection():
    # Will also test false positive detection
    persister = AsyncMock()
    request = Request("http://127.0.0.1:65085/inclusion.php?yolo=nawak&f=toto")
    request.path_id = 42

    crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:65085/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleFile(crawler, persister, options, Event(), crawler_configuration)
        module.do_post = False
        await module.attack(request)

        assert persister.add_payload.call_count == 1
        assert persister.add_payload.call_args_list[0][1]["module"] == "file"
        assert persister.add_payload.call_args_list[0][1]["category"] == "Path Traversal"
        assert ["f", "/etc/services"] in persister.add_payload.call_args_list[0][1]["request"].get_params


@pytest.mark.asyncio
async def test_open_redirect():
    persister = AsyncMock()
    request = Request("http://127.0.0.1:65085/open_redirect.php?url=toto")
    #request.path_id = 42

    crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:65085/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleFile(crawler, persister, options, Event(), crawler_configuration)
        module.do_post = False
        await module.attack(request)

        assert pytest.raises(httpx.InvalidURL)


@pytest.mark.asyncio
async def test_loknop_lfi_to_rce():
    # https://gist.github.com/loknop/b27422d355ea1fd0d90d6dbc1e278d4d
    persister = AsyncMock()
    request = Request("http://127.0.0.1:65085/lfi_with_suffix.php?f=test")
    request.path_id = 42

    crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:65085/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleFile(crawler, persister, options, Event(), crawler_configuration)
        module.do_post = False
        await module.attack(request)

        assert persister.add_payload.call_count == 1
        assert persister.add_payload.call_args_list[0][1]["request"].get_params[0][1].startswith(
            "php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|"
        )


async def delayed_response():
    mock_response = httpx.Response(200, content="Warning: AnotherFunction() Description of the warning \
               root:x:0:0:root:/root:/bin/bash")
    await Sleep(6)
    return mock_response


@pytest.mark.asyncio
async def test_warning_false_positive():
    persister = AsyncMock()
    request = Request("http://127.0.0.1:65085/inclusion.php?yolo=warn&f=toto")
    request.path_id = 42

    crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:65085/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleFile(crawler, persister, options, Event(), crawler_configuration)
        module.do_post = False
        await module.attack(request)

        assert persister.add_payload.call_count == 1
        assert ["f", "/etc/services"] in persister.add_payload.call_args_list[0][1]["request"].get_params


@pytest.mark.asyncio
async def test_no_crash():
    persister = AsyncMock()
    all_requests = []

    request = Request("http://127.0.0.1:65085/empty.html")
    request.path_id = 1
    all_requests.append(request)

    request = Request(
        "http://127.0.0.1:65085/empty.html?foo=bar",
        post_params=[["x", "y"]],
        file_params=[["file", ("fname", b"content", "text/plain")]]
    )
    request.path_id = 2
    all_requests.append(request)

    crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:65085/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleFile(crawler, persister, options, Event(), crawler_configuration)
        module.do_post = False
        for request in all_requests:
            await module.attack(request)

        assert True


def test_prefix_and_suffix_detection():
    assert has_prefix_or_suffix("/etc/passwd", "images//etc/passwd.png") == ["prefix", "suffix"]
    assert has_prefix_or_suffix("/etc/passwd", "/etc/passwd.png") == ["suffix"]
    assert has_prefix_or_suffix("/etc/passwd", "files/etc/passwd") == ["prefix"]
    assert has_prefix_or_suffix("/etc/passwd", "yolo") == []


def test_warning_false_postitives():
    assert find_warning_message(
        (
                "<b>Warning</b>:  include() [<a href=function.include>function.include</a>]: Filename cannot be empty "
                "in <b>/www/index.php</b> on line <b>86</b><br/>\n<br/>\n"
                "<b>Warning</b>:  include() [<a href=function.include>function.include</a>]: Failed opening '' for "
                "inclusion (include_path='.:/usr/local/php/lib64/php') in <b>/www/index.php</b> on line <b>86</b><br/>"
        ),
        "/etc/passwd"
    ) is None

    pattern = (
        "<b>Warning</b>:  file_get_contents() expects parameter 1 to be a valid path, string given in "
        "<b>/home/blah/public_html/skin/blah/page-boatprice.php</b> on line <b>34</b><br />"
    )
    assert find_warning_message(pattern, "http://wapiti3.ovh/e.php[NULL]") is None

    pattern = (
        "<b>Warning</b>:  file_get_contents(): Filename cannot be empty in "
        "<b>/www/doc/blah/www/extdocs/rssReader.php</b> on line <b>319</b><br />"
    )
    assert find_warning_message(pattern, "/etc/passwd") is None


def test_warning_postitives():
    pattern = (
            "Warning: include(): Failed opening 'application/config/tool_http://wapiti3.ovh/e.php.PPGUI.php' for "
            "inclusion (include_path='.:/home/blah/www:/usr/share/php:/usr/share/pear') in /home/blah/www/index.php on "
            "line <i>25</i>"
    )
    assert find_warning_message(
        pattern,
        "http://wapiti3.ovh/e.php"
    ) == FileWarning(
        pattern=pattern,
        uri="application/config/tool_http://wapiti3.ovh/e.php.PPGUI.php",
        function="include()",
        path="/home/blah/www/index.php"
    )

    pattern = (
        "Warning: readfile(bilder//etc/passwd): failed to open stream: No such file or directory "
        "in /home/httpd/vhosts/blah.tld/httpdocs/download.php on line 71"
    )
    assert find_warning_message(
        pattern, "/etc/passwd"
    ) == FileWarning(
        pattern=pattern,
        uri="bilder//etc/passwd",
        function="readfile()",
        path="/home/httpd/vhosts/blah.tld/httpdocs/download.php"
    )

    pattern = (
        "<b>Warning</b>:  include(specialSites/http://wapiti3.ovh/e.php.php): failed to open stream: "
        "No such file or directory in <b>/home/httpd/vhosts/blah/cgi-bin/includePage.php</b> on line <b>227</b>"
    )
    assert find_warning_message(pattern, "http://wapiti3.ovh/e.php") == FileWarning(
        pattern=pattern,
        uri="specialSites/http://wapiti3.ovh/e.php.php",
        function="include()",
        path="/home/httpd/vhosts/blah/cgi-bin/includePage.php"
    )

    pattern = (
        "<b>Warning</b>:  file_get_contents(./http://wapiti3.ovh/e.php/http://wapiti3.ovh/e.php.php): "
        "failed to open stream: No such file or directory in <b>/www/doc/blah/www/index.php</b> on line <b>45</b>"
    )
    assert find_warning_message(pattern, "http://wapiti3.ovh/e.php") == FileWarning(
        pattern=pattern,
        uri="./http://wapiti3.ovh/e.php/http://wapiti3.ovh/e.php.php",
        function="file_get_contents()",
        path="/www/doc/blah/www/index.php"
    )

    pattern = (
        "<b>Warning</b>:  include(blah/etc/services.html) [<a href='function.include'>function.include</a>]: "
        "failed to open stream: No such file or directory in <b>/www/doc/blah/www/page.php</b> on line <b>32</b>"
    )
    assert find_warning_message(
        pattern, "/etc/services"
    ) == FileWarning(
        pattern=pattern,
        uri="blah/etc/services.html",
        path="/www/doc/blah/www/page.php",
        function="include()"

    )

    pattern = (
        "<b>Warning</b>:  include() [<a href='function.include'>function.include</a>]: "
        "Failed opening 'blah/etc/services.html' for inclusion (include_path='.:/usr/share/php') "
        "in <b>/www/doc/blah/www/page.php</b> on line <b>32</b>"
    )
    assert find_warning_message(
        pattern, "/etc/services"
    ) == FileWarning(
        pattern=pattern,
        uri="blah/etc/services.html",
        path="/www/doc/blah/www/page.php",
        function="include()"

    )


if __name__ == "__main__":
    test_inclusion_detection()
