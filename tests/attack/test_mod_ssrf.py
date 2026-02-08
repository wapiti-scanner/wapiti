from unittest.mock import AsyncMock

import httpx
import respx
import pytest

from wapitiCore.attack.attack import ParameterSituation
from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net import Request
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.attack.mod_ssrf import ModuleSsrf, SSRF_INBAND_PAYLOADS


@pytest.mark.asyncio
@respx.mock
async def test_whole_stuff():
    # Test attacking all kind of parameter without crashing
    respx.route(host="perdu.com").mock(return_value=httpx.Response(200, text="Hello there"))

    persister = AsyncMock()
    all_requests = []

    request = Request("http://perdu.com/")
    request.path_id = 1
    all_requests.append(request)

    request = Request("http://perdu.com/?foo=bar")
    request.path_id = 2
    all_requests.append(request)

    request = Request(
        "http://perdu.com/?foo=bar",
        post_params=[["a", "b"]],
        file_params=[["file", ("calendar.xml", b"<xml>Hello there</xml", "application/xml")]]
    )
    request.path_id = 3
    all_requests.append(request)

    def get_path_by_id(request_id):
        for req in all_requests:
            if req.path_id == int(request_id):
                return req
        return None

    persister.get_path_by_id.side_effect = get_path_by_id

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleSsrf(crawler, persister, options, crawler_configuration)
        module.do_post = True

        respx.get("https://wapiti3.ovh/get_ssrf.php?session_id=" + module._session_id).mock(
            return_value=httpx.Response(
                200,
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
        )

        for request in all_requests:
            await module.attack(request)

        assert not persister.add_payload.call_count
        # We must trigger finish() normally called by wapiti.py
        await module.finish()

        assert persister.add_payload.call_count
        assert persister.add_payload.call_args_list[0][1]["module"] == "ssrf"
        assert persister.add_payload.call_args_list[0][1]["category"] == "Server Side Request Forgery"
        assert persister.add_payload.call_args_list[0][1]["parameter"] == "file"
        assert persister.add_payload.call_args_list[0][1]["request"].file_params == [
            ['file', ('http://external.url/page', b'<xml>Hello there</xml', 'application/xml')]
        ]


@pytest.mark.asyncio
@respx.mock
async def test_finish_with_missing_request_id():
    # Test that finish() handles missing request IDs gracefully (no crash)
    respx.route(host="perdu.com").mock(return_value=httpx.Response(200, text="Hello there"))

    persister = AsyncMock()

    request = Request("http://perdu.com/?foo=bar")
    request.path_id = 2

    # get_path_by_id returns None for the unknown request_id "999"
    # but returns the real request for "2"
    def get_path_by_id(request_id):
        if int(request_id) == 2:
            return request
        return None

    persister.get_path_by_id.side_effect = get_path_by_id

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleSsrf(crawler, persister, options, crawler_configuration)
        module.do_post = True

        respx.get("https://wapiti3.ovh/get_ssrf.php?session_id=" + module._session_id).mock(
            return_value=httpx.Response(
                200,
                json={
                    # request_id "999" does not exist in persister
                    "999": {
                        "666f6f": [
                            {
                                "date": "2019-08-17T16:52:41+00:00",
                                "url": "https://wapiti3.ovh/ssrf_data/yolo/999/666f6f/31337-0-10.0.0.1.txt",
                                "ip": "10.0.0.1",
                                "method": "GET"
                            }
                        ]
                    },
                    # request_id "2" exists and should be reported
                    "2": {
                        "666f6f": [
                            {
                                "date": "2019-08-17T16:53:00+00:00",
                                "url": "https://wapiti3.ovh/ssrf_data/yolo/2/666f6f/31337-0-10.0.0.2.txt",
                                "ip": "10.0.0.2",
                                "method": "GET"
                            }
                        ]
                    }
                }
            )
        )

        # finish() should NOT raise ValueError, it should skip the missing ID and process the valid one
        await module.finish()

        assert persister.add_payload.call_count == 1
        assert persister.add_payload.call_args_list[0][1]["parameter"] == "foo"
        assert persister.add_payload.call_args_list[0][1]["category"] == "Server Side Request Forgery"


@pytest.mark.asyncio
@respx.mock
async def test_query_string_injection():
    # Test attacking raw query string (hex-encoded value of QUERY_STRING should appear in payload)
    respx.route(host="perdu.com").mock(return_value=httpx.Response(200, text="Hello there"))

    persister = AsyncMock()
    all_requests = []

    request = Request("http://perdu.com/")
    request.path_id = 1
    all_requests.append(request)

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleSsrf(crawler, persister, options, crawler_configuration)
        module._session_id = "yolo"
        mutated_request, parameter, payload_info = next(module.mutator.mutate(request, module.get_payloads))
        # Make sure get_payloads will correctly inject the session ID and hex-encoded parameter name in such case
        assert mutated_request.url == (
            "http://perdu.com/?http%3A%2F%2Fwapiti3.ovh%2Fssrf%2Fyolo%2F1%2F51554552595f535452494e47%2F"
        )
        assert parameter.name == ""
        assert parameter.situation == ParameterSituation.QUERY_STRING
        assert payload_info.payload == "http://wapiti3.ovh/ssrf/yolo/1/51554552595f535452494e47/"


@pytest.mark.asyncio
@respx.mock
async def test_inband_payloads_generated():
    # Test that get_payloads yields OOB + in-band payloads with correct rules
    respx.route(host="perdu.com").mock(return_value=httpx.Response(200, text="Hello there"))

    persister = AsyncMock()

    request = Request("http://perdu.com/?url=something")
    request.path_id = 1

    crawler_configuration = CrawlerConfiguration(Request("http://perdu.com/"), timeout=1)
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        options = {"timeout": 10, "level": 2}

        module = ModuleSsrf(crawler, persister, options, crawler_configuration)
        module._session_id = "test42"

        payloads = list(module.mutator.mutate(request, module.get_payloads))

        # We expect 1 OOB + N in-band payloads for the "url" parameter
        expected_total = 1 + len(SSRF_INBAND_PAYLOADS)
        assert len(payloads) == expected_total

        # First payload is the OOB one (no rules)
        _, _, first_payload_info = payloads[0]
        assert "ssrf/test42/" in first_payload_info.payload
        assert first_payload_info.rules == []

        # Subsequent payloads are in-band with detection rules
        _, _, second_payload_info = payloads[1]
        assert second_payload_info.payload == "file:///etc/passwd"
        assert "root:x:0:0" in second_payload_info.rules

        # AWS metadata payload should be present
        aws_found = False
        for _, _, payload_info in payloads:
            if "169.254.169.254" in payload_info.payload and "meta-data" in payload_info.payload:
                assert "ami-id" in payload_info.rules
                aws_found = True
        assert aws_found, "AWS metadata payload not found"
