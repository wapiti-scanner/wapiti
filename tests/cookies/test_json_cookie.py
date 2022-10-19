from tempfile import NamedTemporaryFile
import json

import respx
import httpx
import pytest

from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net.jsoncookie import JsonCookie
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.net import Request


@pytest.mark.asyncio
@respx.mock
async def test_cookie_dump():
    with NamedTemporaryFile() as json_fd:
        json_cookie = JsonCookie()
        json_cookie.load(json_fd.name)
        json_cookie.delete("www.destroydestroyboys.com")

        url = "https://www.destroydestroyboys.com/welcome/"
        respx.get(url).mock(
            return_value=httpx.Response(
                200,
                headers=[
                    ("set-cookie", "foo=bar; Path=/"),
                    ("set-cookie", "dead=beef; Path=/welcome/")
                ]
            )
        )

        crawler_configuration = CrawlerConfiguration(Request(url))
        async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
            await crawler.async_get(Request(url))

            json_cookie.addcookies(crawler.cookie_jar)
            json_cookie.dump()

            data = json.load(open(json_fd.name))
            assert data == {
                '.www.destroydestroyboys.com': {
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
