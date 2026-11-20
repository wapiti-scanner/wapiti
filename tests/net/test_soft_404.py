import httpx2

from wapitiCore.net.response import Response
from wapitiCore.net.soft_404 import is_false_positive, probe_dir_name


def make_response(url, status=200, text="", location=None):
    headers = {"location": location} if location else {}
    return Response(httpx2.Response(status, headers=headers, text=text, request=httpx2.Request("GET", url)), url=url)


def test_is_false_positive_flags_identical_soft_404():
    response = make_response("http://perdu.com/some-page", text="Same shell content everywhere")
    not_found_response = make_response("http://perdu.com/zqxjrandom", text="Same shell content everywhere")
    assert is_false_positive(response, not_found_response) is True


def test_is_false_positive_ignores_distinct_200_pages():
    response = make_response("http://perdu.com/some-page", text="Distinct real content for this page only")
    not_found_response = make_response("http://perdu.com/zqxjrandom", text="Totally unrelated other text 12345")
    assert is_false_positive(response, not_found_response) is False


def test_is_false_positive_flags_catch_all_redirection():
    response = make_response("http://perdu.com/some-page", status=302, location="http://perdu.com/login")
    not_found_response = make_response("http://perdu.com/zqxjrandom", status=302, location="http://perdu.com/login")
    assert is_false_positive(response, not_found_response) is True


def test_is_false_positive_does_not_flag_hard_404s():
    # A whole directory locked down (e.g. via .htaccess) or a deliberately broken
    # redirect target returns the exact same 403/404 body as an improbable path, but
    # that's an honest HTTP error, not a soft 404 masking a real page as a success.
    body = "<html><body>Forbidden</body></html>"
    response = make_response("http://perdu.com/admin/private.php", status=403, text=body)
    not_found_response = make_response("http://perdu.com/admin/zqxjrandom", status=403, text=body)
    assert is_false_positive(response, not_found_response) is False


def test_is_false_positive_does_not_flag_hard_404_with_matching_bodies():
    body = "<html><body>Not Found</body></html>"
    response = make_response("http://perdu.com/redirects/broken-target", status=404, text=body)
    not_found_response = make_response("http://perdu.com/redirects/zqxjrandom", status=404, text=body)
    assert is_false_positive(response, not_found_response) is False


def test_probe_dir_name_keeps_real_directories_untouched():
    assert probe_dir_name("http://perdu.com/admin/") == "http://perdu.com/admin/"
    assert probe_dir_name("http://perdu.com/") == "http://perdu.com/"


def test_probe_dir_name_climbs_above_path_info_scripts():
    # /script.php/ isn't a real directory: Apache's AcceptPathInfo routes it (and any
    # extra path after it) straight to script.php, so probing there would just hit
    # the same script again instead of a genuinely unknown path.
    assert probe_dir_name("http://exec/argument_inject.php/") == "http://exec/"
