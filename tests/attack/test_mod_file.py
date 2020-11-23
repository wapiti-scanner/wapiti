from unittest.mock import Mock
from subprocess import Popen
import os
import sys
from time import sleep

import pytest

from wapitiCore.net.web import Request
from wapitiCore.net.crawler import Crawler
from wapitiCore.attack.mod_file import mod_file, has_prefix_or_suffix, find_warning_message, FileWarning


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
                self.vulnerabilities.append((parameter, value))


@pytest.fixture(autouse=True)
def run_around_tests():
    base_dir = os.path.dirname(sys.modules["wapitiCore"].__file__)
    test_directory = os.path.join(base_dir, "..", "tests/data/")

    proc = Popen(["php", "-S", "127.0.0.1:65085", "-a", "-t", test_directory])
    sleep(.5)
    yield
    proc.terminate()


def test_inclusion_detection():
    # Will also test false positive detection
    persister = FakePersister()
    request = Request("http://127.0.0.1:65085/inclusion.php?yolo=nawak&f=toto")
    request.path_id = 42
    persister.requests.append(request)
    crawler = Crawler("http://127.0.0.1:65085/")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_file(crawler, persister, logger, options)
    module.do_post = False
    for __ in module.attack():
        pass

    assert persister.vulnerabilities == [("f", "/etc/services")]


def test_warning_false_positive():
    persister = FakePersister()
    request = Request("http://127.0.0.1:65085/inclusion.php?yolo=warn&f=toto")
    request.path_id = 42
    persister.requests.append(request)
    crawler = Crawler("http://127.0.0.1:65085/")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_file(crawler, persister, logger, options)
    module.do_post = False
    for __ in module.attack():
        pass

    assert persister.vulnerabilities == [("f", "/etc/services")]


def test_no_crash():
    persister = FakePersister()

    request = Request("http://127.0.0.1:65085/empty.html")
    request.path_id = 1
    persister.requests.append(request)

    request = Request(
        "http://127.0.0.1:65085/empty.html?foo=bar",
        post_params=[["x", "y"]],
        file_params=[["file", ["fname", "content"]]]
    )
    request.path_id = 2
    persister.requests.append(request)

    crawler = Crawler("http://127.0.0.1:65085/")
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_file(crawler, persister, logger, options)
    module.do_post = False
    for __ in module.attack():
        pass

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
    assert find_warning_message(pattern, "http://wapiti3.ovh/e.php\0") is None

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
