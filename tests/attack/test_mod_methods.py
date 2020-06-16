import responses

from wapitiCore.net.web import Request
from wapitiCore.net.crawler import Crawler
from wapitiCore.attack.mod_methods import mod_methods
from wapitiCore.language.logger import BaseLogger


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
        self.anomalies.add(request)

    def add_vulnerability(self, request_id: int = -1, category=None, level=0, request=None, parameter="", info=""):
        self.vulnerabilities.append(request)


class FakeLogger(BaseLogger):
    def __init__(self):
        super().__init__()
        self.message = ""

    def log_orange(self, message, *args):
        if message != "---":
            self.message = message


@responses.activate
def test_whole_stuff():
    # Test attacking all kind of parameter without crashing
    responses.add(
        responses.OPTIONS,
        url="http://perdu.com/",
        body="Default page",
        headers={"Allow": "GET,POST,HEAD"}
    )

    responses.add(
        responses.OPTIONS,
        url="http://perdu.com/dav/",
        body="Private section",
        headers={"Allow": "GET,POST,HEAD,PUT"}
    )

    persister = FakePersister()

    request = Request("http://perdu.com/")
    request.path_id = 1
    request.status = 200
    request.set_headers({"content-type": "text/html"})
    persister.requests.append(request)

    request = Request("http://perdu.com/dav/")
    request.path_id = 2
    request.status = 200
    request.set_headers({"content-type": "text/html"})
    persister.requests.append(request)

    crawler = Crawler("http://perdu.com/", timeout=1)
    options = {"timeout": 10, "level": 2}
    logger = FakeLogger()

    module = mod_methods(crawler, persister, logger, options)
    module.verbose = 2
    module.do_get = True
    for __ in module.attack():
        pass

    assert "http://perdu.com/dav/" in logger.message
