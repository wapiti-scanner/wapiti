import unittest
from unittest.mock import MagicMock
import json
import httpx
from wapitiCore.net import Request
from wapitiCore.net.intercepting_explorer import mitm_to_wapiti_request


class TestInterceptingExplorer(unittest.TestCase):
    def test_mitm_to_wapiti_request_get(self):
        mitm_request = MagicMock()
        mitm_request.method = "GET"
        mitm_request.url = "http://example.com/"

        headers_mock = MagicMock()
        headers_mock.items.return_value = [(b"Host", b"example.com"), (b"Referer", b"http://some.referer/")]
        headers_mock.get.side_effect = lambda key, default="": {"Referer": "http://some.referer/"}.get(key, default)
        mitm_request.headers = headers_mock

        mitm_request.urlencoded_form = None
        mitm_request.multipart_form = None
        mitm_request.text = ""

        wapiti_request = mitm_to_wapiti_request(mitm_request)

        self.assertIsInstance(wapiti_request, Request)
        self.assertEqual(wapiti_request.url, "http://example.com/")
        self.assertEqual(wapiti_request.method, "GET")
        self.assertEqual(wapiti_request.referer, "http://some.referer/")
        self.assertEqual(wapiti_request.post_params, [])
        self.assertEqual(wapiti_request.enctype, "")

        expected_headers = httpx.Headers([("host", "example.com"), ("referer", "http://some.referer/")])
        self.assertEqual(wapiti_request.headers, expected_headers)

    def test_post_urlencoded(self):
        mitm_request = MagicMock()
        mitm_request.method = "POST"
        mitm_request.url = "http://example.com/login"

        headers_mock = MagicMock()
        headers_mock.items.return_value = [(b"Content-Type", b"application/x-www-form-urlencoded")]
        headers_mock.get.return_value = "application/x-www-form-urlencoded"
        mitm_request.headers = headers_mock

        form_mock = MagicMock()
        form_mock.items.return_value = [(b"user", b"test"), (b"pass", b"123")]
        mitm_request.urlencoded_form = form_mock
        mitm_request.multipart_form = None
        mitm_request.text = "user=test&pass=123"

        wapiti_request = mitm_to_wapiti_request(mitm_request)
        self.assertEqual(wapiti_request.method, "POST")
        self.assertEqual(wapiti_request.post_params, [("user", "test"), ("pass", "123")])
        self.assertEqual(wapiti_request.enctype, "application/x-www-form-urlencoded")

    def test_post_multipart(self):
        mitm_request = MagicMock()
        mitm_request.method = "POST"
        mitm_request.url = "http://example.com/upload"

        headers_mock = MagicMock()
        headers_mock.items.return_value = [(b"Content-Type", b"multipart/form-data; boundary=...")]
        headers_mock.get.return_value = "multipart/form-data; boundary=..."
        mitm_request.headers = headers_mock

        mitm_request.urlencoded_form = None

        form_mock = MagicMock()
        form_mock.items.return_value = [(b"field1", b"value1")]
        mitm_request.multipart_form = form_mock
        mitm_request.text = ""

        wapiti_request = mitm_to_wapiti_request(mitm_request)
        self.assertEqual(wapiti_request.method, "POST")
        self.assertEqual(wapiti_request.post_params, [("field1", "value1")])
        self.assertEqual(wapiti_request.enctype, "multipart/form-data")

    def test_post_json(self):
        mitm_request = MagicMock()
        mitm_request.method = "POST"
        mitm_request.url = "http://example.com/api"

        headers_mock = MagicMock()
        headers_mock.items.return_value = [(b"Content-Type", b"application/json")]
        headers_mock.get.return_value = "application/json"
        mitm_request.headers = headers_mock

        mitm_request.urlencoded_form = None
        mitm_request.multipart_form = None

        json_data = {"key": "value"}
        mitm_request.text = json.dumps(json_data)

        wapiti_request = mitm_to_wapiti_request(mitm_request)
        self.assertEqual(wapiti_request.method, "POST")
        self.assertEqual(wapiti_request.post_params, json.dumps(json_data))
        self.assertEqual(wapiti_request.enctype, "application/json")

    def test_post_invalid_json(self):
        mitm_request = MagicMock()
        mitm_request.method = "POST"
        mitm_request.url = "http://example.com/api"

        headers_mock = MagicMock()
        headers_mock.items.return_value = [(b"Content-Type", b"application/json")]
        headers_mock.get.return_value = "application/json"
        mitm_request.headers = headers_mock

        mitm_request.urlencoded_form = None
        mitm_request.multipart_form = None
        mitm_request.text = '''{"key": "value"'''  # Invalid JSON

        wapiti_request = mitm_to_wapiti_request(mitm_request)
        self.assertIsNone(wapiti_request)


if __name__ == '__main__':
    unittest.main()
