from pathlib import Path

import httpx
import respx

from wapitiCore.net.crawler import Response
from wapitiCore.parsers.html_parser import Html


@respx.mock
def test_formactions():
    fixture_file = Path(__file__).parent / "data" / "formactions.html"
    with fixture_file.open() as form_action:
        url = "http://perdu.com/"
        respx.get(url).mock(return_value=httpx.Response(200, text=form_action.read()))

        resp = httpx.get(url, follow_redirects=False)
        page = Html(Response(resp).content, url)
        count = 0

        for html_form in page.iter_forms():
            for request in html_form.to_requests():
                count += 1
                if request.file_path == "/form":
                    assert request.post_params == [["name", "doe"]]
                elif request.file_path == "/form2":
                    assert request.post_params == [["name2", "doe"]]
                elif request.file_path == "/":
                    assert request.method == "POST"
                    assert request.post_params[0][1] == "doe"

        assert count == 4
