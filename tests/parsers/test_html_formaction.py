import httpx
import respx

from wapitiCore.net.crawler import Response
from wapitiCore.parsers.html_parser import Html


@respx.mock
def test_formactions():
    with open("tests/data/formactions.html") as form_action:
        url = "http://perdu.com/"
        respx.get(url).mock(return_value=httpx.Response(200, text=form_action.read()))

        resp = httpx.get(url, follow_redirects=False)
        page = Html(Response(resp).content, url)
        count = 0

        for form in page.iter_forms():
            count += 1
            if form.file_path == "/form":
                assert form.post_params == [["name", "doe"]]
            elif form.file_path == "/form2":
                assert form.post_params == [["name2", "doe"]]
            elif form.file_path == "/":
                assert form.method == "POST"
                assert form.post_params[0][1] == "doe"

        assert count == 4
