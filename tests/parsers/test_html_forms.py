import responses
import requests

from wapitiCore.net.crawler import Page


@responses.activate
def test_forms():
    with open("tests/data/forms.html") as fd:
        url = "http://perdu.com/"
        responses.add(
            responses.GET,
            url,
            body=fd.read()
        )

        resp = requests.get(url, allow_redirects=False)
        page = Page(resp, url)
        count = 0

        for form in page.iter_forms():
            count += 1
            if form.file_path == "/get_form":
                assert form.method == "GET"
                assert form.url == "http://perdu.com/get_form?name=default"
                assert form.referer == "http://perdu.com/"
                assert len(form.get_params) == 1
                assert not len(form.post_params)
                assert not len(form.file_params)
                assert not form.is_multipart
            elif form.file_path == "/post_select.php":
                assert form.method == "POST"
                assert form.get_params == [["id", "3"]]
                assert form.post_params ==[["fname", "Smith"], ["csrf", "9877665"], ["carlist", "volvo"]]
                assert form.url == "http://perdu.com/post_select.php?id=3"
                assert not form.is_multipart
                assert not len(form.file_params)

        assert count == 2
