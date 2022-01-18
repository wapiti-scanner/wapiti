import httpx
from wapitiCore.net.web import Request
from wapitiCore.net.web import detail_request, detail_response
from wapitiCore.net.sql_persister import Response

def test_detail_request():
    request = Request("http://perdu.com/", "GET")

    request.set_sent_headers(httpx.Headers([["foo", "bar"]]))
    request._get_params = [["get", "param"]]
    request._post_params = [["post", "param"]]

    detailed_request = detail_request(request)

    assert detailed_request["url"] == "http://perdu.com/?get=param"
    assert detailed_request["method"] == "GET"
    assert detailed_request["headers"] == [("foo", "bar")]
    assert detailed_request["query"] == [["get", "param"]]
    assert detailed_request["body"] == [["post", "param"]]
    assert detailed_request["encoding"] == "UTF-8"


def test_detail_response():
    response = Response(200, httpx.Headers([["foo", "bar"]]), "body")

    detailed_response = detail_response(response)

    assert detailed_response["status_code"] == 200
    assert detailed_response["body"] == "body"
    assert detailed_response["headers"] == [("foo", "bar")]
