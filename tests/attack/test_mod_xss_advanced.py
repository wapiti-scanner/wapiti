from unittest.mock import Mock
from subprocess import Popen
import os
import sys
from time import sleep

import pytest

from wapitiCore.net.web import Request
from wapitiCore.net.crawler import Crawler
from wapitiCore.attack.mod_xss import mod_xss
from wapitiCore.language.vulnerability import _


class FakePersister:
    def __init__(self):
        self.requests = []
        self.additionals = set()
        self.anomalies = set()
        self.vulnerabilities = []

    def get_links(self, path=None, attack_module: str = ""):
        return self.requests

    def add_additional(self, request_id: int = -1, category=None, level=0, request=None, parameter="", info=""):
        self.additionals.add(request)

    def add_anomaly(self, request_id: int = -1, category=None, level=0, request=None, parameter="", info=""):
        self.anomalies.add(parameter)

    def add_vulnerability(self, request_id: int = -1, category=None, level=0, request=None, parameter="", info=""):
        for parameter_name, value in request.get_params:
            if parameter_name == parameter:
                self.vulnerabilities.append((parameter, value, info))


@pytest.fixture(autouse=True)
def run_around_tests():
    base_dir = os.path.dirname(sys.modules["wapitiCore"].__file__)
    test_directory = os.path.join(base_dir, "..", "tests/data/xss/")

    proc = Popen(["php", "-S", "127.0.0.1:65081", "-a", "-t", test_directory])
    sleep(.5)
    yield
    proc.terminate()


def test_title_false_positive():
    # We should fail at escaping the title tag and we should be aware of it
    persister = FakePersister()
    request = Request("http://127.0.0.1:65081/title_false_positive.php?title=yolo&fixed=yes")
    request.path_id = 42
    persister.requests.append(request)
    crawler = Crawler("http://127.0.0.1:65081/")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_xss(crawler, persister, logger, options)
    module.do_post = False
    for __ in module.attack():
        pass

    assert persister.vulnerabilities == []


def test_title_positive():
    # We should succeed at escaping the title tag
    persister = FakePersister()
    request = Request("http://127.0.0.1:65081/title_false_positive.php?title=yolo")
    request.path_id = 42
    persister.requests.append(request)
    crawler = Crawler("http://127.0.0.1:65081/")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_xss(crawler, persister, logger, options)
    module.do_post = False
    for __ in module.attack():
        pass

    assert persister.vulnerabilities
    assert persister.vulnerabilities[0][0] == "title"
    assert persister.vulnerabilities[0][1].startswith("</title>")
    assert _("Warning: Content-Security-Policy is present!") not in persister.vulnerabilities[0][2]


def test_script_filter_bypass():
    # We should succeed at bypass the <script filter
    persister = FakePersister()
    request = Request("http://127.0.0.1:65081/script_tag_filter.php?name=kenobi")
    request.path_id = 42
    persister.requests.append(request)
    crawler = Crawler("http://127.0.0.1:65081/")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_xss(crawler, persister, logger, options)
    module.do_post = False
    for __ in module.attack():
        pass

    assert persister.vulnerabilities
    assert persister.vulnerabilities[0][0] == "name"
    assert persister.vulnerabilities[0][1].lower().startswith("<svg")


def test_attr_quote_escape():
    # We should succeed at closing the attribute value and the opening tag
    persister = FakePersister()
    request = Request("http://127.0.0.1:65081/attr_quote_escape.php?class=custom")
    request.path_id = 42
    persister.requests.append(request)
    crawler = Crawler("http://127.0.0.1:65081/")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_xss(crawler, persister, logger, options)
    module.do_post = False
    for __ in module.attack():
        pass

    assert persister.vulnerabilities
    assert persister.vulnerabilities[0][0] == "class"
    assert persister.vulnerabilities[0][1].lower().startswith("'></pre>")


def test_attr_double_quote_escape():
    # We should succeed at closing the attribute value and the opening tag
    persister = FakePersister()
    request = Request("http://127.0.0.1:65081/attr_double_quote_escape.php?class=custom")
    request.path_id = 42
    persister.requests.append(request)
    crawler = Crawler("http://127.0.0.1:65081/")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_xss(crawler, persister, logger, options)
    module.do_post = False
    for __ in module.attack():
        pass

    assert persister.vulnerabilities
    assert persister.vulnerabilities[0][0] == "class"
    assert persister.vulnerabilities[0][1].lower().startswith("\"></pre>")


def test_attr_escape():
    # We should succeed at closing the attribute value and the opening tag
    persister = FakePersister()
    request = Request("http://127.0.0.1:65081/attr_escape.php?state=checked")
    request.path_id = 42
    persister.requests.append(request)
    crawler = Crawler("http://127.0.0.1:65081/")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_xss(crawler, persister, logger, options)
    module.do_post = False
    for __ in module.attack():
        pass

    assert persister.vulnerabilities
    assert persister.vulnerabilities[0][0] == "state"
    assert persister.vulnerabilities[0][1].lower().startswith("><script>")


def test_tag_name_escape():
    # We should succeed at closing the attribute value and the opening tag
    persister = FakePersister()
    request = Request("http://127.0.0.1:65081/tag_name_escape.php?tag=textarea")
    request.path_id = 42
    persister.requests.append(request)
    crawler = Crawler("http://127.0.0.1:65081/")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_xss(crawler, persister, logger, options)
    module.do_post = False
    for __ in module.attack():
        pass

    assert persister.vulnerabilities
    assert persister.vulnerabilities[0][0] == "tag"
    assert persister.vulnerabilities[0][1].lower().startswith("script>")


def test_partial_tag_name_escape():
    # We should succeed at closing the attribute value and the opening tag
    persister = FakePersister()
    request = Request("http://127.0.0.1:65081/partial_tag_name_escape.php?importance=2")
    request.path_id = 42
    persister.requests.append(request)
    crawler = Crawler("http://127.0.0.1:65081/")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_xss(crawler, persister, logger, options)
    module.do_post = False
    for __ in module.attack():
        pass

    assert persister.vulnerabilities
    assert persister.vulnerabilities[0][0] == "importance"
    assert persister.vulnerabilities[0][1].lower().startswith("/><script>")


def test_xss_inside_tag_input():
    persister = FakePersister()
    request = Request("http://127.0.0.1:65081/input_text_strip_tags.php?uid=5")
    request.path_id = 42
    persister.requests.append(request)
    crawler = Crawler("http://127.0.0.1:65081/")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_xss(crawler, persister, logger, options)
    module.do_post = False
    for __ in module.attack():
        pass

    assert persister.vulnerabilities
    assert persister.vulnerabilities[0][0] == "uid"
    used_payload = persister.vulnerabilities[0][1].lower()
    assert "<" not in used_payload and ">" not in used_payload and "autofocus/onfocus" in used_payload


def test_xss_inside_tag_link():
    persister = FakePersister()
    request = Request("http://127.0.0.1:65081/link_href_strip_tags.php?url=http://perdu.com/")
    request.path_id = 42
    persister.requests.append(request)
    crawler = Crawler("http://127.0.0.1:65081/")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_xss(crawler, persister, logger, options)
    module.do_post = False
    for __ in module.attack():
        pass

    assert persister.vulnerabilities
    assert persister.vulnerabilities[0][0] == "url"
    used_payload = persister.vulnerabilities[0][1].lower()
    assert "<" not in used_payload and ">" not in used_payload and "autofocus href onfocus" in used_payload


def test_xss_uppercase_no_script():
    persister = FakePersister()
    request = Request("http://127.0.0.1:65081/uppercase_no_script.php?name=obiwan")
    request.path_id = 42
    persister.requests.append(request)
    crawler = Crawler("http://127.0.0.1:65081/")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_xss(crawler, persister, logger, options)
    module.do_post = False
    for __ in module.attack():
        pass

    assert persister.vulnerabilities
    assert persister.vulnerabilities[0][0] == "name"
    used_payload = persister.vulnerabilities[0][1].lower()
    assert used_payload.startswith("<svg onload=&")


def test_frame_src_escape():
    persister = FakePersister()
    request = Request("http://127.0.0.1:65081/frame_src_escape.php?url=https://wapiti.sourceforge.io/")
    request.path_id = 42
    persister.requests.append(request)
    crawler = Crawler("http://127.0.0.1:65081/")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_xss(crawler, persister, logger, options)
    module.do_post = False
    for __ in module.attack():
        pass

    assert persister.vulnerabilities
    assert persister.vulnerabilities[0][0] == "url"
    used_payload = persister.vulnerabilities[0][1].lower()
    assert used_payload.startswith('"><frame src="javascript:alert(/w')


def test_frame_src_no_escape():
    persister = FakePersister()
    request = Request("http://127.0.0.1:65081/frame_src_no_escape.php?url=https://wapiti.sourceforge.io/")
    request.path_id = 42
    persister.requests.append(request)
    crawler = Crawler("http://127.0.0.1:65081/")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_xss(crawler, persister, logger, options)
    module.do_post = False
    for __ in module.attack():
        pass

    assert persister.vulnerabilities
    assert persister.vulnerabilities[0][0] == "url"
    used_payload = persister.vulnerabilities[0][1].lower()
    assert used_payload.startswith("javascript:alert(/w")


def test_bad_separator_used():
    persister = FakePersister()
    request = Request("http://127.0.0.1:65081/confuse_separator.php?number=42")
    request.path_id = 42
    persister.requests.append(request)
    crawler = Crawler("http://127.0.0.1:65081/")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_xss(crawler, persister, logger, options)
    module.do_post = False
    for __ in module.attack():
        pass

    assert persister.vulnerabilities
    used_payload = persister.vulnerabilities[0][1].lower()
    assert used_payload.startswith("\">")


def test_escape_with_style():
    persister = FakePersister()
    request = Request("http://127.0.0.1:65081/escape_with_style.php?color=green")
    request.path_id = 42
    persister.requests.append(request)
    crawler = Crawler("http://127.0.0.1:65081/")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_xss(crawler, persister, logger, options)
    module.do_post = False
    for __ in module.attack():
        pass

    assert persister.vulnerabilities
    used_payload = persister.vulnerabilities[0][1].lower()
    assert used_payload.startswith("</style>")


def test_rare_tag_and_event():
    persister = FakePersister()
    request = Request("http://127.0.0.1:65081/filter_common_keywords.php?msg=test")
    request.path_id = 42
    persister.requests.append(request)
    crawler = Crawler("http://127.0.0.1:65081/")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_xss(crawler, persister, logger, options)
    module.do_post = False
    for __ in module.attack():
        pass

    assert persister.vulnerabilities
    used_payload = persister.vulnerabilities[0][1].lower()
    assert used_payload.startswith("<custom\nchecked\nonpointerenter=")


def test_xss_with_strong_csp():
    persister = FakePersister()
    request = Request("http://127.0.0.1:65081/strong_csp.php?content=Hello%20there")
    request.path_id = 42
    persister.requests.append(request)
    crawler = Crawler("http://127.0.0.1:65081/")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_xss(crawler, persister, logger, options)
    module.do_post = False
    for __ in module.attack():
        pass

    assert persister.vulnerabilities
    assert _("Warning: Content-Security-Policy is present!") in persister.vulnerabilities[0][2]


def test_xss_with_weak_csp():
    persister = FakePersister()
    request = Request("http://127.0.0.1:65081/weak_csp.php?content=Hello%20there")
    request.path_id = 42
    persister.requests.append(request)
    crawler = Crawler("http://127.0.0.1:65081/")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_xss(crawler, persister, logger, options)
    module.do_post = False
    for __ in module.attack():
        pass

    assert persister.vulnerabilities
    assert _("Warning: Content-Security-Policy is present!") not in persister.vulnerabilities[0][2]
