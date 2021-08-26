#!/usr/bin/env python3

from httpx import Response, Request
from wapitiCore.net.page import Page

def test_make_absolute():

    TEST_CASES = [
        ("http://base.url", "relative", "http://base.url/relative"),
        ("http://base.url", ".", "http://base.url/"),
        ("http://base.url/with_folder", ".", "http://base.url/"),
        ("http://base.url/with_folder", "./with_dot", "http://base.url/with_dot"),
        ("http://base.url/with_folder", "..", "http://base.url/"),
        ("http://base.url/with_folder", "../folder", "http://base.url/folder"),
        ("http://base.url", "http://whole.url", "http://whole.url/"),
        ("http://base.url", "https://whole.url", "https://whole.url/"),
        ("http://base.url", "http://whole.url:987", "http://whole.url:987/"),
        ("http://base.url", "https://whole.url:987", "https://whole.url:987/"),
        ("http://base.url", "/", "http://base.url/"),
        ("http://base.url", "//", ""),
        ("http://base.url", "//only_this", "http://only_this/"),
        ("http://base.url", "./..//", "http://base.url/"),
        ("http://base.url", "./wrong_folder/../good_folder/", "http://base.url/good_folder/"),
    ]

    request = Request("GET", "http://base.url")
    response = Response(status_code=200, request=request)
    page = Page(response)

    for base_url, relative_url, expected in TEST_CASES:
        page._base = base_url
        assert page.make_absolute(relative_url) == expected, \
            f"Absolute url from base_url='{base_url}' and relative_url='{relative_url}' is not '{expected}'"
