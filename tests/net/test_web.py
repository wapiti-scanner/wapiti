import httpx

from wapitiCore.net.web import detail_response
from wapitiCore.net.sql_persister import Response


def test_detail_response():
    response = Response(200, httpx.Headers([["foo", "bar"]]), "body")

    detailed_response = detail_response(response)

    assert detailed_response["status_code"] == 200
    assert detailed_response["body"] == "body"
    assert detailed_response["headers"] == [("foo", "bar")]
