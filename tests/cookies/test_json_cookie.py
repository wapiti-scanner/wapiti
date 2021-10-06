from tempfile import NamedTemporaryFile
import json

import respx
import httpx
import pytest

from wapitiCore.net.jsoncookie import JsonCookie
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.net.web import Request


@pytest.mark.asyncio
@respx.mock
async def test_cookie_dump():
    with NamedTemporaryFile() as json_fd:
        json_cookie = JsonCookie()
        json_cookie.load(json_fd.name)
        json_cookie.delete("httpbin.org")

        url = "http://httpbin.org/welcome/"
        respx.get(url).mock(
            return_value=httpx.Response(
                200,
                headers=[
                    ("set-cookie", "foo=bar; Path=/"),
                    ("set-cookie", "dead=beef; Path=/welcome/")
                ]
            )
        )

        crawler = AsyncCrawler(url)
        await crawler.async_get(Request(url))

        json_cookie.addcookies(crawler.session_cookies)

        await crawler.close()
        json_cookie.dump()

        data = json.load(open(json_fd.name))
        assert data == {
            '.httpbin.org': {
                '/': {
                    'foo': {
                        'expires': None,
                        'port': None,
                        'secure': False,
                        'value': 'bar',
                        'version': 0
                    }
                },
                '/welcome/': {
                    'dead': {
                        'expires': None,
                        'port': None,
                        'secure': False,
                        'value': 'beef',
                        'version': 0
                    }
                }
            }
        }


@pytest.mark.asyncio
async def test_cookie_load():
    with NamedTemporaryFile(mode="w") as json_fd:
        data = {
            '.httpbin.org': {
                '/': {
                    'foo': {
                        'expires': None,
                        'port': None,
                        'secure': False,
                        'value': 'bar',
                        'version': 0
                    }
                },
                '/welcome/': {
                    'dead': {
                        'expires': None,
                        'port': None,
                        'secure': False,
                        'value': 'beef',
                        'version': 0
                    }
                }
            }
        }
        json.dump(data, json_fd)
        json_cookie = JsonCookie()
        json_cookie.load(json_fd.name)
        jar = json_cookie.cookiejar("httpbin.org")
        for cookie in jar:
            assert (cookie.name == "foo" and cookie.value == "bar" and cookie.path == "/") or\
                   (cookie.name == "dead" and cookie.value == "beef" and cookie.path == "/welcome/")
        json_cookie.dump()


@pytest.mark.asyncio
async def test_cookie_delete():
    with NamedTemporaryFile(mode="w") as json_fd:
        data = {
            '.httpbin.org': {
                '/': {
                    'foo': {
                        'expires': None,
                        'port': None,
                        'secure': False,
                        'value': 'bar',
                        'version': 0
                    }
                },
                '/welcome/': {
                    'dead': {
                        'expires': None,
                        'port': None,
                        'secure': False,
                        'value': 'beef',
                        'version': 0
                    }
                }
            }
        }
        json.dump(data, json_fd)
        json_cookie = JsonCookie()
        json_cookie.load(json_fd.name)
        json_cookie.delete("httpbin.org")
        json_cookie.dump()

        assert open(json_fd.name).read() == '{}'
