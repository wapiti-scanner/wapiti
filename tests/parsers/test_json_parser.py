import responses
import requests

from wapitiCore.net.crawler import Page


@responses.activate
def test_json():
    url = "http://perdu.com/"
    responses.add(
        responses.GET,
        url,
        json={"key": "v4lu3"},
        status=200,
        adding_headers={
            "Content-Type": "application/json"
        }
    )

    resp = requests.get(url)
    page = Page(resp)

    assert page.json["key"] == "v4lu3"
