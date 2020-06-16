from unittest.mock import Mock

import responses

from wapitiCore.net.web import Request
from wapitiCore.net.crawler import Crawler
from wapitiCore.attack.mod_ssrf import mod_ssrf


class FakePersister:
    def __init__(self):
        self.requests = []
        self.additionals = set()
        self.anomalies = set()
        self.vulnerabilities = []

    def get_links(self, path=None, attack_module: str = ""):
        return self.requests

    def get_forms(self, attack_module: str = ""):
        return [request for request in self.requests if request.method == "POST"]

    def get_path_by_id(self, path_id):
        for request in self.requests:
            if request.path_id == int(path_id):
                return request
        return None

    def add_additional(self, request_id: int = -1, category=None, level=0, request=None, parameter="", info=""):
        self.additionals.add(request)

    def add_anomaly(self, request_id: int = -1, category=None, level=0, request=None, parameter="", info=""):
        self.anomalies.add((parameter, request))

    def add_vulnerability(self, request_id: int = -1, category=None, level=0, request=None, parameter="", info=""):
        self.vulnerabilities.append((parameter, request))


@responses.activate
def test_whole_stuff():
    # Test attacking all kind of parameter without crashing
    responses.add(
        responses.GET,
        url="http://perdu.com/",
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

    module = mod_ssrf(crawler, persister, logger, options)
    module.verbose = 2
    module.do_post = True

    responses.add(
        responses.GET,
        url="https://wapiti3.ovh/get_ssrf.php?id=" + module._session_id,
        json={
            "3": {
                "66696c65": [
                    {
                        "date": "2019-08-17T16:52:41+00:00",
                        "url": "https://wapiti3.ovh/ssrf_data/yolo/3/66696c65/31337-0-192.168.2.1.txt",
                        "ip": "192.168.2.1",
                        "method": "GET"
                    }
                ]
            }
        }
    )

    for __ in module.attack():
        pass

    assert not persister.vulnerabilities
    # We must trigger finish(à normally called by wapiti.py
    module.finish()

    assert persister.vulnerabilities
    assert persister.vulnerabilities[0][0] == "file"
    file_params = persister.vulnerabilities[0][1].file_params
    assert file_params[0][1][0] == "http://external.url/page"
