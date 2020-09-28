import responses
import requests

from wapitiCore.net.crawler import Page


@responses.activate
def test_absolute_root():
    with open("tests/data/absolute_root_links.html") as data_body:
        url = "http://perdu.com/"
        responses.add(
            responses.GET,
            url,
            body=data_body.read()
        )

        resp = requests.get(url)
        page = Page(resp)

        assert page.links == [url]


@responses.activate
def test_relative_root():
    with open("tests/data/relative_root_links.html") as data_body:
        url = "http://perdu.com/"
        responses.add(
            responses.GET,
            url,
            body=data_body.read()
        )

        resp = requests.get(url)
        page = Page(resp)

        # We will get invalid hostnames with dots. Browsers do that too.
        assert set(page.links) == {url, "http://./", "http://../"}


@responses.activate
def test_relative_links():
    with open("tests/data/relative_links.html") as data_body:
        url = "http://perdu.com/"
        responses.add(
            responses.GET,
            url,
            body=data_body.read()
        )

        resp = requests.get(url)
        page = Page(resp)

        assert set(page.links) == {
            url,
            "http://perdu.com/file.html",
            "http://perdu.com/resource",
            "http://perdu.com/folder/",
            "http://perdu.com/folder/file.html",
            "http://perdu.com/folder/file2.html",
            "http://perdu.com/file3.html",
            "http://perdu.com/?k=v",
            "http://perdu.com/file3.html?k=v",
            "http://perdu.com/folder/?k=v",
            "http://perdu.com/folder?k=v",
            "http://external.tld/",
            "http://external.tld/yolo?k=v",
        }


@responses.activate
def test_other_links():
    with open("tests/data/other_links.html") as data_body:
        url = "http://perdu.com/"
        responses.add(
            responses.GET,
            url,
            body=data_body.read(),
            adding_headers={
                "Location": "https://perdu.com/login"
            },
            status=301
        )

        resp = requests.get(url, allow_redirects=False)
        page = Page(resp)

        assert sorted(page.iter_frames()) == [
            "http://perdu.com/frame1.html",
            "http://perdu.com/frame2.html",
            "http://perdu.com/iframe.html"
        ]
        assert page.scripts == ["http://perdu.com/script.js"]
        assert page.redirection_url == "https://perdu.com/login"
        assert set(page.images_urls) == {
            "http://perdu.com/img/logo.png",
            "http://perdu.com/img/header.png",
            "http://perdu.com/img/ads.php?id=5878545"
        }
        assert page.js_redirections == ["http://perdu.com/maintenance.html"]
        assert page.favicon_url == "http://perdu.com/favicon.ico"
        assert page.html_redirections == ["http://perdu.com/adblock.html"]


@responses.activate
def test_extra_links():
    with open("tests/data/extra_links.html") as data_body:
        url = "http://perdu.com/"
        responses.add(
            responses.GET,
            url,
            body=data_body.read()
        )

        resp = requests.get(url, allow_redirects=False)
        page = Page(resp)

        assert set(page.extra_urls) == {
            "http://perdu.com/planets.gif",
            "http://perdu.com/sun.html",
            "http://perdu.com/mercur.html",
            "http://perdu.com/venus.html",
            "http://perdu.com/link.html",
            "http://perdu.com/audio.html",
            "http://perdu.com/embed.html",
            "http://perdu.com/horse.ogg",
            "http://perdu.com/horse.mp3",
            "http://perdu.com/video.html",
            "http://perdu.com/subtitles_en.vtt",
            "http://perdu.com/dopequote.html",
            "http://perdu.com/del.html",
            "http://perdu.com/ins.html",
            "http://perdu.com/q.html",
            "http://perdu.com/data.html",
            "http://perdu.com/high-def.jpg",
            "http://perdu.com/low-def.jpg",
            "http://perdu.com/img_orange_flowers.jpg",
            "http://perdu.com/style.css?should_not_be_crawled",
            "http://perdu.com/yolo.js?v=53"
        }


@responses.activate
def test_meta():
    with open("tests/data/meta.html") as data_body:
        url = "http://perdu.com/"
        responses.add(
            responses.GET,
            url,
            body=data_body.read()
        )

        resp = requests.get(url, allow_redirects=False)
        page = Page(resp)

        assert page.title == "  -  Title :) "
        assert page.description == "Meta page"
        assert page.keywords == ["this", "is", " dope"]
        assert page.generator == "YoloCMS 1.0"
        assert page.text_only == "This is dope"
        assert page.favicon_url == "http://perdu.com/custom.ico"
        assert page.md5 == "2778718d04cfa16ffd264bd76b0cf18b"


@responses.activate
def test_base_relative_links():
    with open("tests/data/base_relative_links.html") as data_body:
        url = "http://perdu.com/"
        responses.add(
            responses.GET,
            url,
            body=data_body.read()
        )

        resp = requests.get(url)
        page = Page(resp)

        assert set(page.links) == {
            url,
            "http://perdu.com/blog/file.html",
            "http://perdu.com/blog/resource",
            "http://perdu.com/blog/folder/",
            "http://perdu.com/blog/folder/file.html",
            "http://perdu.com/blog/folder/file2.html",
            "http://perdu.com/folder/file2.html",
            "http://perdu.com/",
            "http://perdu.com/blog/",
            "http://perdu.com/blog/file3.html",
            "http://perdu.com/blog/?k=v",
            "http://perdu.com/blog/?k=v2",
            "http://perdu.com/blog/file3.html?k=v",
            "http://perdu.com/blog/folder/?k=v",
            "http://perdu.com/blog/folder?k=v",
            "http://external.tld/",
            "http://external.tld/yolo?k=v",
        }


@responses.activate
def test_base_extra_links():
    with open("tests/data/base_extra_links.html") as data_body:
        url = "http://perdu.com/"
        responses.add(
            responses.GET,
            url,
            body=data_body.read()
        )

        resp = requests.get(url, allow_redirects=False)
        page = Page(resp)

        assert set(page.extra_urls) == {
            "http://perdu.com/blog/",  # extracted from base href
            "http://perdu.com/blog/planets.gif",
            "http://perdu.com/blog/sun.html",
            "http://perdu.com/blog/mercur.html",
            "http://perdu.com/blog/venus.html",
            "http://perdu.com/blog/link.html",
            "http://perdu.com/blog/audio.html",
            "http://perdu.com/blog/embed.html",
            "http://perdu.com/blog/horse.ogg",
            "http://perdu.com/blog/horse.mp3",
            "http://perdu.com/blog/video.html",
            "http://perdu.com/blog/subtitles_en.vtt",
            "http://perdu.com/blog/dopequote.html",
            "http://perdu.com/blog/del.html",
            "http://perdu.com/blog/ins.html",
            "http://perdu.com/blog/q.html",
            "http://perdu.com/blog/data.html",
            "http://perdu.com/blog/high-def.jpg",
            "http://perdu.com/blog/low-def.jpg",
            "http://perdu.com/blog/img_orange_flowers.jpg"
        }


@responses.activate
def test_base_other_links():
    with open("tests/data/base_other_links.html") as data_body:
        url = "http://perdu.com/"
        responses.add(
            responses.GET,
            url,
            body=data_body.read(),
            adding_headers={
                "Location": "https://perdu.com/login"
            },
            status=301
        )

        resp = requests.get(url, allow_redirects=False)
        page = Page(resp)

        assert sorted(page.iter_frames()) == [
            "http://perdu.com/blog/frame1.html",
            "http://perdu.com/blog/frame2.html",
            "http://perdu.com/blog/iframe.html"
        ]

        assert page.scripts == ["http://perdu.com/blog/script.js"]
        assert page.redirection_url == "https://perdu.com/login"
        assert set(page.images_urls) == {
            "http://perdu.com/blog/img/logo.png"
        }

        assert page.html_redirections == ["http://perdu.com/blog/adblock.html"]
