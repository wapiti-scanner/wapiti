import httpx

from wapitiCore.net.web import detail_response
from wapitiCore.net.sql_persister import Response


def test_detail_response():
    response = Response(httpx.Response(200, headers=httpx.Headers([["foo", "bar"]]), content=b"body"))

    detailed_response = detail_response(response)

    assert detailed_response["status_code"] == 200
    assert detailed_response["body"] == "body"
    assert ("foo", "bar") in detailed_response["headers"]  # Content-Length is present too
