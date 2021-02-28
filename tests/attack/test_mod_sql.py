from unittest.mock import Mock
import re
from urllib.parse import urlparse, parse_qs
from tempfile import NamedTemporaryFile
import sqlite3

import responses

from wapitiCore.net.web import Request
from wapitiCore.net.crawler import Crawler
from wapitiCore.attack.mod_sql import mod_sql


class FakePersister:
    def __init__(self):
        self.requests = []
        self.additionals = set()
        self.anomalies = set()
        self.vulnerabilities = []

    def get_links(self, path=None, attack_module: str = ""):
        return [request for request in self.requests if request.method == "GET"]

    def get_forms(self, attack_module: str = ""):
        return [request for request in self.requests if request.method == "POST"]

    def add_additional(self, request_id: int = -1, category=None, level=0, request=None, parameter="", info=""):
        self.additionals.add(request)

    def add_anomaly(self, request_id: int = -1, category=None, level=0, request=None, parameter="", info=""):
        self.anomalies.add(parameter)

    def add_vulnerability(self, request_id: int = -1, category=None, level=0, request=None, parameter="", info=""):
        for parameter_name, value in request.get_params:
            if parameter_name == parameter:
                self.vulnerabilities.append((parameter, value))


@responses.activate
def test_whole_stuff():
    # Test attacking all kind of parameter without crashing
    responses.add(
        responses.GET,
        re.compile(r"http://perdu.com/"),
        body="Hello there"
    )

    responses.add(
        responses.POST,
        re.compile(r"http://perdu.com/"),
        body="Hello there"
    )

    persister = FakePersister()

    request = Request("http://perdu.com/")
    request.path_id = 1
    persister.requests.append(request)

    request = Request("http://perdu.com/?foo=bar")
    request.path_id = 2
    persister.requests.append(request)

    request = Request(
        "http://perdu.com/?foo=bar",
        post_params=[["a", "b"]],
        file_params=[["file", ["calendar.xml", "<xml>Hello there</xml"]]]
    )
    request.path_id = 3
    persister.requests.append(request)

    crawler = Crawler("http://perdu.com/", timeout=1)
    options = {"timeout": 10, "level": 2}
    logger = Mock()

    module = mod_sql(crawler, persister, logger, options)
    module.verbose = 2
    module.do_post = True
    for request in persister.requests:
        module.attack(request)

    assert True


@responses.activate
def test_false_positive():
    responses.add(
        responses.GET,
        url="http://perdu.com/",
        body="You have an error in your SQL syntax"
    )

    persister = FakePersister()

    request = Request("http://perdu.com/?foo=bar")
    request.path_id = 1

    crawler = Crawler("http://perdu.com/", timeout=1)
    options = {"timeout": 10, "level": 1}
    logger = Mock()

    module = mod_sql(crawler, persister, logger, options)
    module.verbose = 2
    module.do_post = True
    module.attack(request)

    assert not persister.vulnerabilities


@responses.activate
def test_true_positive():
    responses.add(
        responses.GET,
        url="http://perdu.com/?foo=bar",
        body="Hi there"
    )

    responses.add(
        responses.GET,
        url=re.compile(r"http://perdu.com/\?foo=.*"),
        body=(
            "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version "
            "for the right syntax to use near '\\\"\\'' at line 1"
        )
    )

    persister = FakePersister()

    request = Request("http://perdu.com/?foo=bar")
    request.path_id = 1

    crawler = Crawler("http://perdu.com/", timeout=1)
    options = {"timeout": 10, "level": 1}
    logger = Mock()

    module = mod_sql(crawler, persister, logger, options)
    module.verbose = 2
    module.do_post = True
    module.attack(request)

    assert persister.vulnerabilities


@responses.activate
def test_blind_detection():
    with NamedTemporaryFile() as database_fd:
        conn = sqlite3.connect(database_fd.name)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
        conn.commit()
        cursor.execute("INSERT INTO users (id, username, password) VALUES (1, \"admin\", \"123456\")")
        conn.commit()
        cursor.close()
        conn.close()

        def process(http_request):
            try:
                user_id = parse_qs(urlparse(http_request.url).query)["user_id"][0]
            except (IndexError, KeyError):
                return 200, {}, "Unknown user"
            else:
                conn = sqlite3.connect(database_fd.name)
                cursor = conn.cursor()
                try:
                    # Will you spot the SQLi vulnerability? :D
                    cursor.execute("SELECT username FROM users WHERE id = {}".format(user_id))
                    row = cursor.fetchone()
                except sqlite3.OperationalError:
                    cursor.close()
                    conn.close()
                    return 200, {}, "Unknown user"
                else:
                    cursor.close()
                    conn.close()
                    if row:
                        return 200, {}, "Welcome {}".format(row[0])
                    else:
                        return 200, {}, "Unknown user"

        responses.add_callback(
            responses.GET,
            re.compile(r"http://perdu.com/\?user_id=.*"),
            callback=process
        )

        persister = FakePersister()

        request = Request("http://perdu.com/?user_id=1")
        request.path_id = 1

        crawler = Crawler("http://perdu.com/", timeout=1)
        options = {"timeout": 10, "level": 1}
        logger = Mock()

        module = mod_sql(crawler, persister, logger, options)
        module.verbose = 2
        module.do_post = True
        module.attack(request)

        assert persister.vulnerabilities
        # One request for error-based, one to get normal response, four to test boolean-based attack
        assert len(responses.calls) == 6


@responses.activate
def test_negative_blind():
    responses.add(
        responses.GET,
        url="http://perdu.com/",
        body="Hello there"
    )

    persister = FakePersister()

    request = Request("http://perdu.com/?foo=bar")
    request.path_id = 1

    crawler = Crawler("http://perdu.com/", timeout=1)
    options = {"timeout": 10, "level": 1}
    logger = Mock()

    module = mod_sql(crawler, persister, logger, options)
    module.verbose = 2
    module.attack(request)

    assert not persister.vulnerabilities
    # We have:
    # - 1 request for error-based test
    # - 1 request to get normal response
    # - 2*3 requests for the first test of each "session" (as the first test fails others are skipped)
    assert len(responses.calls) == 8


@responses.activate
def test_blind_detection_parenthesis():
    with NamedTemporaryFile() as database_fd:
        conn = sqlite3.connect(database_fd.name)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
        conn.commit()
        cursor.execute("INSERT INTO users (id, username, password) VALUES (1, \"admin\", \"123456\")")
        conn.commit()
        cursor.close()
        conn.close()

        def process(http_request):
            try:
                username = parse_qs(urlparse(http_request.url).query)["username"][0]
            except (IndexError, KeyError):
                return 200, {}, "Unknown user"
            else:
                conn = sqlite3.connect(database_fd.name)
                cursor = conn.cursor()
                try:
                    # Will you spot the SQLi vulnerability? :D
                    cursor.execute("SELECT id FROM users WHERE username = '{}'".format(username))
                    row = cursor.fetchone()
                except sqlite3.OperationalError:
                    cursor.close()
                    conn.close()
                    return 200, {}, "Unknown user"
                else:
                    cursor.close()
                    conn.close()
                    if row:
                        return 200, {}, "Welcome, your user ID is {}".format(row[0])
                    else:
                        return 200, {}, "Unknown user"

        responses.add_callback(
            responses.GET,
            re.compile(r"http://perdu.com/\?username=.*"),
            callback=process
        )

        persister = FakePersister()

        request = Request("http://perdu.com/?username=admin")
        request.path_id = 1

        crawler = Crawler("http://perdu.com/", timeout=1)
        options = {"timeout": 10, "level": 1}
        logger = Mock()

        module = mod_sql(crawler, persister, logger, options)
        module.verbose = 2
        module.do_post = True
        module.attack(request)

        assert persister.vulnerabilities
        # This is the same test as the previous blind except we have to put single quotes
        assert len(responses.calls) == 8
