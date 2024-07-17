import re
from subprocess import Popen
import os
import sys
from time import sleep
from asyncio import Event
from unittest.mock import AsyncMock

import pytest

from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_xss import ModuleXss


@pytest.fixture(autouse=True)
def run_around_tests():
    base_dir = os.path.dirname(sys.modules["wapitiCore"].__file__)
    test_directory = os.path.join(base_dir, "..", "tests/data/xss/")

    proc = Popen(["php", "-S", "127.0.0.1:65081", "-a", "-t", test_directory])
    sleep(.5)
    yield
    proc.terminate()


@pytest.mark.asyncio
async def test_title_false_positive():
    # We should fail at escaping the title tag, and we should be aware of it
    persister = AsyncMock()
    request = Request("http://127.0.0.1:65081/title_false_positive.php?title=yolo&fixed=yes")
    request.path_id = 42
    crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:65081/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleXss(crawler, persister, options, Event(), crawler_configuration)
        module.do_post = False
        await module.attack(request)

        assert not persister.add_payload.call_count


@pytest.mark.asyncio
async def test_title_positive():
    # We should succeed at escaping the title tag
    persister = AsyncMock()
    request = Request("http://127.0.0.1:65081/title_false_positive.php?title=yolo")
    request.path_id = 42
    crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:65081/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleXss(crawler, persister, options, Event(), crawler_configuration)
        module.do_post = False
        await module.attack(request)

        assert persister.add_payload.call_count
        assert persister.add_payload.call_args_list[0][1]["module"] == "xss"
        assert persister.add_payload.call_args_list[0][1]["category"] == "Reflected Cross Site Scripting"
        assert persister.add_payload.call_args_list[0][1]["parameter"] == "title"
        assert persister.add_payload.call_args_list[0][1]["request"].get_params[0][1].startswith("</title>")
        assert "Warning: Content-Security-Policy is present!" not in persister.add_payload.call_args_list[0][1]["info"]


@pytest.mark.asyncio
async def test_script_filter_bypass():
    # We should succeed at bypass the <script filter
    persister = AsyncMock()
    request = Request("http://127.0.0.1:65081/script_tag_filter.php?name=kenobi")
    request.path_id = 42
    crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:65081/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleXss(crawler, persister, options, Event(), crawler_configuration)
        module.do_post = False
        await module.attack(request)

        assert persister.add_payload.call_count
        assert persister.add_payload.call_args_list[0][1]["parameter"] == "name"
        assert persister.add_payload.call_args_list[0][1]["request"].get_params[0][1].lower().startswith("<svg")


@pytest.mark.asyncio
async def test_script_src_protocol_relative():
    # The PHP script is blocking "http" and "("
    persister = AsyncMock()
    request = Request("http://127.0.0.1:65081/no_http_no_parenthesis.php?name=kenobi")
    request.path_id = 42
    crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:65081/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleXss(crawler, persister, options, Event(), crawler_configuration)
        module.do_post = False
        await module.attack(request)

        assert persister.add_payload.call_count
        assert persister.add_payload.call_args_list[0][1]["parameter"] == "name"
        used_payload = persister.add_payload.call_args_list[0][1]["request"].get_params[0][1].lower()
        assert used_payload.startswith("<script src=//")
        assert "wapiti3.ovh" not in used_payload


@pytest.mark.asyncio
async def test_attr_quote_escape():
    # We should succeed at closing the attribute value and the opening tag
    persister = AsyncMock()
    request = Request("http://127.0.0.1:65081/attr_quote_escape.php?class=custom")
    request.path_id = 42
    crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:65081/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleXss(crawler, persister, options, Event(), crawler_configuration)
        module.do_post = False
        await module.attack(request)

        assert persister.add_payload.call_count
        assert persister.add_payload.call_args_list[0][1]["parameter"] == "class"
        assert persister.add_payload.call_args_list[0][1]["request"].get_params[0][1].lower().startswith("'></pre>")


@pytest.mark.asyncio
async def test_attr_double_quote_escape():
    # We should succeed at closing the attribute value and the opening tag
    persister = AsyncMock()
    request = Request("http://127.0.0.1:65081/attr_double_quote_escape.php?class=custom")
    request.path_id = 42
    crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:65081/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleXss(crawler, persister, options, Event(), crawler_configuration)
        module.do_post = False
        await module.attack(request)

        assert persister.add_payload.call_count
        assert persister.add_payload.call_args_list[0][1]["parameter"] == "class"
        assert persister.add_payload.call_args_list[0][1]["request"].get_params[0][1].lower().startswith("\"></pre>")


@pytest.mark.asyncio
async def test_attr_escape():
    # We should succeed at closing the attribute value and the opening tag
    persister = AsyncMock()
    request = Request("http://127.0.0.1:65081/attr_escape.php?state=checked")
    request.path_id = 42
    crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:65081/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleXss(crawler, persister, options, Event(), crawler_configuration)
        module.do_post = False
        await module.attack(request)

        assert persister.add_payload.call_count
        assert persister.add_payload.call_args_list[0][1]["parameter"] == "state"
        assert persister.add_payload.call_args_list[0][1]["request"].get_params[0][1].lower().startswith("><script>")


@pytest.mark.asyncio
async def test_tag_name_escape():
    # We should succeed at closing the attribute value and the opening tag
    persister = AsyncMock()
    request = Request("http://127.0.0.1:65081/tag_name_escape.php?tag=textarea")
    request.path_id = 42
    crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:65081/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleXss(crawler, persister, options, Event(), crawler_configuration)
        module.do_post = False
        await module.attack(request)

        assert persister.add_payload.call_count
        assert persister.add_payload.call_args_list[0][1]["parameter"] == "tag"
        assert persister.add_payload.call_args_list[0][1]["request"].get_params[0][1].lower().startswith("script>")


@pytest.mark.asyncio
async def test_partial_tag_name_escape():
    # We should succeed at closing the attribute value and the opening tag
    persister = AsyncMock()
    request = Request("http://127.0.0.1:65081/partial_tag_name_escape.php?importance=2")
    request.path_id = 42
    crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:65081/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleXss(crawler, persister, options, Event(), crawler_configuration)
        module.do_post = False
        await module.attack(request)

        assert persister.add_payload.call_count
        assert persister.add_payload.call_args_list[0][1]["parameter"] == "importance"
        assert persister.add_payload.call_args_list[0][1]["request"].get_params[0][1].lower().startswith("/><script>")


@pytest.mark.asyncio
async def test_xss_inside_tag_input():
    persister = AsyncMock()
    request = Request("http://127.0.0.1:65081/input_text_strip_tags.php?uid=5")
    request.path_id = 42
    crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:65081/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleXss(crawler, persister, options, Event(), crawler_configuration)
        module.do_post = False
        await module.attack(request)

        assert persister.add_payload.call_count
        assert persister.add_payload.call_args_list[0][1]["parameter"] == "uid"
        used_payload = persister.add_payload.call_args_list[0][1]["request"].get_params[0][1].lower()
        assert "<" not in used_payload and ">" not in used_payload and "autofocus/onfocus" in used_payload


@pytest.mark.asyncio
async def test_xss_inside_tag_link():
    persister = AsyncMock()
    request = Request("http://127.0.0.1:65081/link_href_strip_tags.php?url=http://perdu.com/")
    request.path_id = 42
    crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:65081/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleXss(crawler, persister, options, Event(), crawler_configuration)
        module.do_post = False
        await module.attack(request)

        assert persister.add_payload.call_count
        assert persister.add_payload.call_args_list[0][1]["parameter"] == "url"
        used_payload = persister.add_payload.call_args_list[0][1]["request"].get_params[0][1].lower()
        assert "<" not in used_payload and ">" not in used_payload and "autofocus href onfocus" in used_payload


@pytest.mark.asyncio
async def test_xss_inside_href_link():
    persister = AsyncMock()
    request = Request("http://127.0.0.1:65081/link_href_htmlentities.php?url=http://perdu.com/")
    request.path_id = 42
    crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:65081/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleXss(crawler, persister, options, Event(), crawler_configuration)
        module.do_post = False
        await module.attack(request)

        assert persister.add_payload.call_count
        assert persister.add_payload.call_args_list[0][1]["parameter"] == "url"
        used_payload = persister.add_payload.call_args_list[0][1]["request"].get_params[0][1].lower()
        assert "<" not in used_payload and ">" not in used_payload and "javascript:alert" in used_payload


@pytest.mark.asyncio
async def test_xss_inside_src_iframe():
    persister = AsyncMock()
    request = Request("http://127.0.0.1:65081/iframe_src_htmlentities.php?url=http://perdu.com/")
    request.path_id = 42
    crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:65081/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleXss(crawler, persister, options, Event(), crawler_configuration)
        module.do_post = False
        await module.attack(request)

        assert persister.add_payload.call_count
        assert persister.add_payload.call_args_list[0][1]["parameter"] == "url"
        used_payload = persister.add_payload.call_args_list[0][1]["request"].get_params[0][1].lower()
        assert "<" not in used_payload and ">" not in used_payload and "javascript:alert" in used_payload


@pytest.mark.asyncio
async def test_xss_uppercase_no_script():
    persister = AsyncMock()
    request = Request("http://127.0.0.1:65081/uppercase_no_script.php?name=obiwan")
    request.path_id = 42
    crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:65081/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleXss(crawler, persister, options, Event(), crawler_configuration)
        module.do_post = False
        await module.attack(request)

        assert persister.add_payload.call_count
        assert persister.add_payload.call_args_list[0][1]["parameter"] == "name"
        used_payload = persister.add_payload.call_args_list[0][1]["request"].get_params[0][1].lower()
        assert used_payload.startswith("<svg onload=&")


@pytest.mark.asyncio
async def test_frame_src_escape():
    persister = AsyncMock()
    request = Request("http://127.0.0.1:65081/frame_src_escape.php?url=https://wapiti-scanner.github.io/")
    request.path_id = 42
    crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:65081/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleXss(crawler, persister, options, Event(), crawler_configuration)
        module.do_post = False
        await module.attack(request)

        assert persister.add_payload.call_count
        assert persister.add_payload.call_args_list[0][1]["parameter"] == "url"
        used_payload = persister.add_payload.call_args_list[0][1]["request"].get_params[0][1].lower()
        assert used_payload.startswith('"><frame src="javascript:alert(/w')


@pytest.mark.asyncio
async def test_frame_src_no_escape():
    persister = AsyncMock()
    request = Request("http://127.0.0.1:65081/frame_src_no_escape.php?url=https://wapiti-scanner.github.io/")
    request.path_id = 42
    crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:65081/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleXss(crawler, persister, options, Event(), crawler_configuration)
        module.do_post = False
        await module.attack(request)

        assert persister.add_payload.call_count
        assert persister.add_payload.call_args_list[0][1]["parameter"] == "url"
        used_payload = persister.add_payload.call_args_list[0][1]["request"].get_params[0][1].lower()
        assert used_payload.startswith("javascript:alert(/w")


@pytest.mark.asyncio
async def test_bad_separator_used():
    persister = AsyncMock()
    request = Request("http://127.0.0.1:65081/confuse_separator.php?number=42")
    request.path_id = 42
    crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:65081/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleXss(crawler, persister, options, Event(), crawler_configuration)
        module.do_post = False
        await module.attack(request)

        assert persister.add_payload.call_count
        used_payload = persister.add_payload.call_args_list[0][1]["request"].get_params[0][1].lower()
        assert used_payload.startswith("\">")


@pytest.mark.asyncio
async def test_escape_with_style():
    persister = AsyncMock()
    request = Request("http://127.0.0.1:65081/escape_with_style.php?color=green")
    request.path_id = 42
    crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:65081/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleXss(crawler, persister, options, Event(), crawler_configuration)
        module.do_post = False
        await module.attack(request)

        assert persister.add_payload.call_count
        used_payload = persister.add_payload.call_args_list[0][1]["request"].get_params[0][1].lower()
        assert used_payload.startswith("</style>")


@pytest.mark.asyncio
async def test_rare_tag_and_event():
    persister = AsyncMock()
    request = Request("http://127.0.0.1:65081/filter_common_keywords.php?msg=test")
    request.path_id = 42
    crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:65081/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleXss(crawler, persister, options, Event(), crawler_configuration)
        module.do_post = False
        await module.attack(request)

        assert persister.add_payload.call_count
        used_payload = persister.add_payload.call_args_list[0][1]["request"].get_params[0][1].lower()
        assert used_payload.startswith("<custom\nchecked\nonpointerenter=")


@pytest.mark.asyncio
async def test_xss_with_strong_csp():
    persister = AsyncMock()
    request = Request("http://127.0.0.1:65081/strong_csp.php?content=Hello%20there")
    request.path_id = 42
    crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:65081/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleXss(crawler, persister, options, Event(), crawler_configuration)
        module.do_post = False
        await module.attack(request)

        assert persister.add_payload.call_count
        assert "Warning: Content-Security-Policy is present!" in persister.add_payload.call_args_list[0][1]["info"]


@pytest.mark.asyncio
async def test_xss_with_weak_csp():
    persister = AsyncMock()
    request = Request("http://127.0.0.1:65081/weak_csp.php?content=Hello%20there")
    request.path_id = 42
    crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:65081/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleXss(crawler, persister, options, Event(), crawler_configuration)
        module.do_post = False
        await module.attack(request)

        assert persister.add_payload.call_count
        assert "Warning: Content-Security-Policy is present!" not in persister.add_payload.call_args_list[0][1]["info"]


@pytest.mark.asyncio
async def test_fallback_to_html_injection():
    persister = AsyncMock()
    request = Request("http://127.0.0.1:65081/no_js_possible.php?name=test")
    request.path_id = 42
    crawler_configuration = CrawlerConfiguration(Request("http://127.0.0.1:65081/"))
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleXss(crawler, persister, options, Event(), crawler_configuration)
        module.do_post = False
        await module.attack(request)

        assert persister.add_payload.call_count
        assert persister.add_payload.call_args_list[0][1]["parameter"] == "name"
        assert persister.add_payload.call_args_list[0][1]["category"] == "HTML Injection"
        assert persister.add_payload.call_args_list[0][1]["info"] == (
            "HTML Injection vulnerability found via injection in the parameter name"
        )
        used_payload = persister.add_payload.call_args_list[0][1]["request"].get_params[0][1].lower()
        assert re.match(r'<div id="\w+">yolo</div>', used_payload)

