from unittest.mock import patch
import argparse
from tempfile import NamedTemporaryFile
import json

import pytest
import respx
import httpx

from wapitiCore.main.getcookie import getcookie_main


@pytest.mark.asyncio
@respx.mock
@patch('argparse.ArgumentParser.parse_args')
async def test_command(mock_args):
    with NamedTemporaryFile("w") as json_fd:
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

        mock_args.return_value = argparse.Namespace(
            url="http://httpbin.org/welcome/",
            cookie=json_fd.name,
            proxy=None,
            tor=None,
            headers=[],
            data=None
        )
        await getcookie_main()

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


