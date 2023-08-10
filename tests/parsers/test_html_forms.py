from wapitiCore.parsers.html_parser import Html


def test_forms():
    with open("tests/data/forms.html") as data_body:
        url = "http://perdu.com/"
        page = Html(data_body.read(), url)
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
                    "date": "2023-03-03",
                    "datetime": "2023-03-03T20:35:34.32",
                    "datetime-local": "2023-03-03T22:41",
                    "email": "wapiti2021@mailinator.com",
                    "file": "pix.gif",
                    "gender": "other",  # taking the last one
                    "hidden": "default",
                    "image.x": "1",
                    "image.y": "1",
                    "month": "2023-03",
                    "number": "1337",
                    "password": "Letm3in_",
                    "radio": "on",
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
    page = Html(body, url)

    form = next(page.iter_forms())
    assert "@" in form.post_params[0][1]


def test_button_without_value():
    url = "https://crazyandthebrains.net/"
    body = """<html>
    <body>
        <form method="POST" action="/post">
            <input type=text name="text" /><br />
            <button name="btn" type=submit>submit</button>
        </form>
    """

    page = Html(body, url)

    form = next(page.iter_forms())
    assert form.post_params == [["text", "default"], ["btn", ""]]


def test_wordpress_comment_form():
    # Given a form with either non-editable (hidden) fields but default values
    # or fields we autofill
    # or fields with a required attribute
    url = "http://wordpress.com/"
    body = """
    <form action="http://wordpress.com/wp-comments-post.php" method="post" id="commentform" novalidate>
      <textarea id="comment" name="comment" required></textarea>
      <input id="author" name="author" type="text" value="" autocomplete="name" required />
      <input id="email" name="email" type="email" value="" autocomplete="email" required />
      <input id="url" name="url" type="url" value="" autocomplete="url" />
      <input id="wp-comment-cookies-consent" name="wp-comment-cookies-consent" type="checkbox" value="yes" />
      <input name="submit" type="submit" id="submit"  value="Post Comment" />
      <input type='hidden' name='comment_post_ID' value='4' id='comment_post_ID' />
      <input type='hidden' name='comment_parent' id='comment_parent' value='0' />
    </form>
    """

    # When we extract forms
    page = Html(body, url)
    form = next(page.iter_forms())
    # We expect all fields to have values (no empty string)
    assert all(value for _, value in form.post_params)


def test_missing_required():
    # Given a form with fields having default values
    # and some with empty string as default without the "required" attribute
    url = "http://wordpress.com/"
    body = """
    <form action="http://wordpress.com/wp-comments-post.php" method="post" id="commentform" novalidate>
      <textarea id="comment" name="comment"></textarea>
      <input id="author" name="author" type="text" value="" autocomplete="name" />
      <input id="email" name="email" type="email" value="" autocomplete="email" />
      <input id="url" name="url" type="url" value="" autocomplete="url" />
      <input id="wp-comment-cookies-consent" name="wp-comment-cookies-consent" type="checkbox" value="yes" />
      <input name="submit" type="submit" id="submit"  value="Post Comment" />
      <input type='hidden' name='comment_post_ID' value='4' id='comment_post_ID' />
      <input type='hidden' name='comment_parent' id='comment_parent' value='0' />
    </form>
    """

    # When we extract forms with autofill to False
    page = Html(body, url)
    form = next(page.iter_forms(autofill=False))
    # We expect the fields to not be filled
    assert [
        ['author', ''],
        ['email', ''],
        ['url', ''],
        ['wp-comment-cookies-consent', 'yes'],
        ['submit', 'Post Comment'],
        ['comment_post_ID', '4'],
        ['comment_parent', '0'],
        ['comment', '']
    ] == form.post_params
