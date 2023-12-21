from multiprocessing import Process
import os
import sys
from time import sleep
from asyncio import Event
import http.server
import ssl
from unittest.mock import AsyncMock

import pytest

from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net import Request
from wapitiCore.language.vulnerability import CRITICAL_LEVEL, HIGH_LEVEL, INFO_LEVEL
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_ssl import ModuleSsl, NAME


def https_server(cert_directory: str):
    server_address = ("127.0.0.1", 4443)
    httpd = http.server.HTTPServer(server_address, http.server.SimpleHTTPRequestHandler)
    httpd.socket = ssl.wrap_socket(
        httpd.socket,
        server_side=True,
        certfile=os.path.join(cert_directory, "cert.pem"),
        keyfile=os.path.join(cert_directory, "key.pem"),
        ssl_version=ssl.PROTOCOL_TLS
    )
    httpd.serve_forever()


@pytest.fixture(autouse=True)
def run_around_tests():
    base_dir = os.path.dirname(sys.modules["wapitiCore"].__file__)
    pem_directory = os.path.join(base_dir, "..", "tests/data/ssl/")

    process = Process(target=https_server, args=(pem_directory,))
    process.start()

    sleep(.5)
    yield
    process.kill()


@pytest.mark.asyncio
async def test_ssl_scanner():
    persister = AsyncMock()
    request = Request("https://127.0.0.1:4443/")
    request.path_id = 42
    crawler_configuration = CrawlerConfiguration(Request("https://127.0.0.1:4443/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleSsl(crawler, persister, options, Event(), crawler_configuration)
        await module.attack(request)

        # Depending on installed python/openssl version different vulnerabilities may be present but the following
        # vulnerabilities and information should be there everytime

        persister.add_payload.assert_any_call(
            request_id=-1,
            payload_type="additional",
            module="ssl",
            category=NAME,
            level=INFO_LEVEL,
            request=request,
            parameter='',
            wstg=["WSTG-CRYP-01"],
            info="Certificate subject: yolo.com",
            response=None
        )

        # persister.add_payload.assert_any_call(
        #     request_id=-1,
        #     payload_type="vulnerability",
        #     module="ssl",
        #     category=NAME,
        #     level=CRITICAL_LEVEL,
        #     request=request,
        #     parameter='',
        #     wstg=["WSTG-CRYP-01"],
        #     info="Requested hostname doesn't match those in the certificate",
        #     response=None
        # )

        # persister.add_payload.assert_any_call(
        #     request_id=-1,
        #     payload_type="vulnerability",
        #     module="ssl",
        #     category=NAME,
        #     level=CRITICAL_LEVEL,
        #     request=request,
        #     parameter='',
        #     wstg=["WSTG-CRYP-01"],
        #     info="Certificate is invalid for Mozilla trust store: self-signed certificate",
        #     response=None
        # )

        persister.add_payload.assert_any_call(
            request_id=-1,
            payload_type="vulnerability",
            module="ssl",
            category=NAME,
            level=HIGH_LEVEL,
            request=request,
            parameter='',
            wstg=["WSTG-CRYP-01"],
            info="Strict Transport Security (HSTS) is not set",
            response=None
        )
