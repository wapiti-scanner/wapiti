import respx
import httpx

from wapitiCore.net.crawler import Response


@respx.mock
def test_json():
    url = "http://perdu.com/"
    respx.get(url).mock(
        return_value=httpx.Response(200, json={"key": "v4lu3"}, headers={"Content-Type": "application/json"})
    )

    resp = httpx.get(url)
    page = Response(resp)

    assert page.json["key"] == "v4lu3"
