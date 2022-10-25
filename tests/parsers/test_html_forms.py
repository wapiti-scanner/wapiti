import respx
import httpx

from wapitiCore.net.crawler import Response
from wapitiCore.parsers.html_parser import Html


@respx.mock
def test_forms():
    with open("tests/data/forms.html") as data_body:
        url = "http://perdu.com/"
        respx.get(url).mock(return_value=httpx.Response(200, text=data_body.read()))

        resp = httpx.get(url, follow_redirects=False)
        page = Html(Response(resp).content, url)
        count = 0
        form_action = False

        for form in page.iter_forms():
            count += 1
            if form.file_path == "/get_form":
                assert form.method == "GET"
                assert form.url == "http://perdu.com/get_form?name=default"
                assert form.referer == "http://perdu.com/"
                assert len(form.get_params) == 1
                assert not form.post_params
                assert not form.file_params
                assert not form.is_multipart
            elif form.file_path == "/post_select.php":
                assert form.method == "POST"
                assert form.get_params == [["id", "3"]]
                assert form.post_params == [["fname", "Smith"], ["csrf", "9877665"], ["carlist", "volvo"]]
                assert form.url == "http://perdu.com/post_select.php?id=3"
                assert not form.is_multipart
                assert not form.file_params
            elif form.file_path == "/fields.php":
                assert form.method == "POST"
                assert not form.is_multipart
                assert len([gender[1] for gender in form.post_params if gender[0] == "gender"]) == 1

                assert dict(form.post_params) == {
                    "vehicle1": "car",
                    "vehicle2": "boat",
                    "color": "#bada55",
                    "date": "2019-03-03",
                    "datetime": "2019-03-03T20:35:34.32",
                    "datetime-local": "2019-03-03T22:41",
                    "email": "wapiti2021@mailinator.com",
                    "file": "pix.gif",
                    "gender": "other",  # taking the last one
                    "hidden": "default",
                    "image.x": "1",
                    "image.y": "1",
                    "month": "2019-03",
                    "number": "1337",
                    "password": "Letm3in_",
                    "radio": "beton",
                    "range": "37",
                    "search": "default",
                    "submit": "submit",
                    "tel": "0606060606",
                    "text": "default",
                    "textarea": "Hi there!",
                    "time": "13:37",
                    "url": "https://wapiti-scanner.github.io/",
                    "week": "2019-W24"
                }
            elif form.file_path == "/upload.php":
                assert form.is_multipart
                assert not form.post_params
                assert form.file_params == [["file", ("pix.gif", b"GIF89a", "image/gif")]]
            elif form.file_path == "/alt.php":
                form_action = True
            elif form.file_path == "/upload_empty_value.php":
                assert form.file_params == [["file", ("pix.gif", b"GIF89a", "image/gif")]]
            elif form.file_path == "/select_no_defaults.php":
                items = dict(form.post_params)
                assert items["choices"] == "3rd_choice"
            else:
                # Form with no action set
                assert form.file_path == "/"

        assert count == 9
        assert form_action


@respx.mock
def test_email_input():
    url = "http://perdu.com/"
    body = """<html>
    <body>
    <form method="POST">
    <input type="text" name="email_address" />
    </form>
    </body>
    </html>
    """

    respx.get(url).mock(return_value=httpx.Response(200, text=body))

    resp = httpx.get(url, follow_redirects=False)
    page = Html(Response(resp).content, url)

    form = next(page.iter_forms())
    assert "@" in form.post_params[0][1]


@respx.mock
def test_button_without_value():
    url = "https://crazyandthebrains.net/"
    body = """<html>
    <body>
        <form method="POST" action="/post">
            <input type=text name="text" /><br />
            <button name="btn" type=submit>submit</button>
        </form>
    """

    respx.get(url).mock(return_value=httpx.Response(200, text=body))

    resp = httpx.get(url, follow_redirects=False)
    page = Html(Response(resp).content, url)

    form = next(page.iter_forms())
    assert form.post_params == [["text", "default"], ["btn", ""]]
