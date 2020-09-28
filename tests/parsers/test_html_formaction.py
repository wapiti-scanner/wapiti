import responses
import requests

from wapitiCore.net.crawler import Page


@responses.activate
def test_formactions():
    with open("tests/data/formactions.html") as form_action:
        url = "http://perdu.com/"
        responses.add(
            responses.GET,
            url,
            body=form_action.read()
        )

        resp = requests.get(url, allow_redirects=False)
        page = Page(resp)
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
