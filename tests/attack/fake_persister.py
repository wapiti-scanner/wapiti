import os

class FakePersister:

    CONFIG_DIR_NAME = "config"
    HOME_DIR = os.getenv("HOME") or os.getenv("USERPROFILE")
    BASE_DIR = os.path.join(HOME_DIR, ".wapiti")
    CONFIG_DIR = os.path.join(BASE_DIR, CONFIG_DIR_NAME)

    def __init__(self):
        self.requests = []
        self.module = None
        self.category = None
        self.payloads = {"additional": [], "anomaly": [], "vulnerability": []}

    def get_links(self, _path=None, attack_module: str = ""):
        for request in self.requests:
            if request.method == "GET":
                yield request

    def get_forms(self, attack_module: str = ""):
        return [request for request in self.requests if request.method == "POST"]

    def get_path_by_id(self, path_id):
        for request in self.requests:
            if request.path_id == int(path_id):
                return request
        return None

    @property
    def vulnerabilities(self):
        return self.payloads["vulnerability"]

    @property
    def anomalies(self):
        return self.payloads["anomaly"]

    @property
    def additionals(self):
        return self.payloads["additional"]

    def add_payload(self, request_id: int, payload_type: str, module: str,
            category=None, level=0, request=None, parameter="", info=""):
        self.payloads[payload_type].append({
            "level": level, "request_id": request_id, "request": request,
            "parameter": parameter, "info" :info, "category": category
            })
        print(self.payloads)
        self.module = module
