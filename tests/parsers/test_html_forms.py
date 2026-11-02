from pathlib import Path

import pytest

from wapitiCore.parsers.html_parser import Html

LOGIN_URL = "http://perdu.com/login"

# Named controls stay in document order whatever the nameless decorations around them.
USER_FIELD = '<input type="text" name="username" value="u1">'
PASSWORD_FIELD = '<input type="password" name="password" value="p1">'
HIDDEN_FIELD = '<input type="hidden" name="csrf" value="tok-42">'
SUBMIT_FIELD = '<input type="submit" name="commit" value="Sign in">'
NAMELESS_CONTROLS = (
    '<input type="hidden">'
    '<input type="checkbox" checked>'
    '<input type="text" value="decorative">'
)

EXPECTED_PARAMS = [
    ["csrf", "tok-42"],
    ["username", "u1"],
    ["password", "p1"],
    ["commit", "Sign in"],
]

LOGIN_FORMS = {
    "clean": HIDDEN_FIELD + USER_FIELD + PASSWORD_FIELD + SUBMIT_FIELD,
    "nameless-before": NAMELESS_CONTROLS + HIDDEN_FIELD + USER_FIELD + PASSWORD_FIELD + SUBMIT_FIELD,
    "nameless-between": HIDDEN_FIELD + USER_FIELD + NAMELESS_CONTROLS + PASSWORD_FIELD + SUBMIT_FIELD,
    "nameless-after": HIDDEN_FIELD + USER_FIELD + PASSWORD_FIELD + SUBMIT_FIELD + NAMELESS_CONTROLS,
}


def _login_form_page(method: str, fields: str) -> Html:
    body = f'<html><body><form action="/login" method="{method}">{fields}</form></body></html>'
    return Html(body, LOGIN_URL)


def test_forms():
    fixture = Path(__file__).parent / "data" / "forms.html"
    with fixture.open() as data_body:
        url = "http://perdu.com/"
        page = Html(data_body.read(), url)
        count = 0
        form_action = False

        for form in page.iter_forms():
            for form_request in form.to_requests():
                count += 1

                if form_request.file_path == "/get_form":
                    assert form_request.method == "GET"
                    assert form_request.url == "http://perdu.com/get_form?name=default"
                    assert form_request.referer == "http://perdu.com/"
                    assert len(form_request.get_params) == 1
                    assert not form_request.post_params
                    assert not form_request.file_params
                    assert not form_request.is_multipart
                elif form_request.file_path == "/post_select.php":
                    assert form_request.method == "POST"
                    assert form_request.get_params == [["id", "3"]]
                    assert form_request.post_params == [["fname", "Smith"], ["csrf", "9877665"], ["carlist", "volvo"]]
                    assert form_request.url == "http://perdu.com/post_select.php?id=3"
                    assert not form_request.is_multipart
                    assert not form_request.file_params
                elif form_request.file_path == "/fields.php":
                    assert form_request.method == "POST"
                    assert not form_request.is_multipart
                    assert len([gender[1] for gender in form_request.post_params if gender[0] == "gender"]) == 1

                    assert dict(form_request.post_params) == {
                        "vehicle1": "car",
                        "vehicle2": "boat",
                        "color": "#bada55",
                        "date": "2023-03-03",
                        "datetime": "2023-03-03T20:35:34.32",
                        "datetime-local": "2023-03-03T22:41",
                        "email": "wapiti2021@mailinator.com",
                        "file": "pix.gif",
                        "gender": "female",  # taking the selected one if any
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
                elif form_request.file_path == "/upload.php":
                    assert form_request.is_multipart
                    assert not form_request.post_params
                    assert form_request.file_params == [["file", ("pix.gif", b"GIF89a", "image/gif")]]
                elif form_request.file_path == "/alt.php":
                    form_action = True
                elif form_request.file_path == "/upload_empty_value.php":
                    assert form_request.file_params == [["file", ("pix.gif", b"GIF89a", "image/gif")]]
                elif form_request.file_path == "/select_no_defaults.php":
                    items = dict(form_request.post_params)
                    assert items["choices"] == "3rd_choice"
                else:
                    # Form with no action set
                    assert form_request.file_path == "/"

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
    request = form.to_requests()[0]
    assert "@" in request.post_params[0][1]


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

    request = next(page.iter_forms()).to_requests()[0]
    assert request.post_params == [["text", "default"], ["btn", ""]]


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
    request = form.to_requests()[0]
    # We expect all fields to have values (no empty string)
    assert all(value for _, value in request.post_params)


@pytest.mark.parametrize("method", ["GET", "POST"])
@pytest.mark.parametrize("case", sorted(LOGIN_FORMS))
def test_login_form_indexes_match_request_params(method: str, case: str):
    """Returned indexes must address the same named inputs used to build Request parameters."""
    login_form, username_idx, password_idx = _login_form_page(method, LOGIN_FORMS[case]).find_login_form()

    assert login_form is not None
    assert login_form.method == method
    assert login_form.file_path == "/login"

    params = login_form.get_params if method == "GET" else login_form.post_params
    unused_params = login_form.post_params if method == "GET" else login_form.get_params
    assert params == EXPECTED_PARAMS
    assert unused_params == []

    assert (username_idx, password_idx) == (1, 2)
    assert 0 <= username_idx < len(params)
    assert 0 <= password_idx < len(params)
    assert params[username_idx] == ["username", "u1"]
    assert params[password_idx] == ["password", "p1"]


def test_nameless_identity_and_password_inputs_are_not_indexed():
    """A nameless email/password pair must not hide a properly named login pair."""
    fields = (
        '<input type="email">'
        '<input type="password">'
        '<input type="text" name="username" value="u1">'
        '<input type="password" name="password" value="p1">'
    )
    login_form, username_idx, password_idx = _login_form_page("POST", fields).find_login_form()

    assert login_form is not None
    assert login_form.post_params == [["username", "u1"], ["password", "p1"]]
    assert (username_idx, password_idx) == (0, 1)
    assert 0 <= username_idx < len(login_form.post_params)
    assert 0 <= password_idx < len(login_form.post_params)


def test_form_with_only_nameless_identity_fields_is_not_a_login_form():
    """Nameless identity/password controls alone must not make a form a login form."""
    fields = (
        '<input type="email">'
        '<input type="password">'
        '<input type="text" name="search" value="q">'
    )
    assert _login_form_page("POST", fields).find_login_form() == (None, 0, 0)
