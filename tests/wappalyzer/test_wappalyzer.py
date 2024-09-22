from typing import Dict
from unittest import mock
from unittest.mock import MagicMock, mock_open

import respx
import httpx
import pytest

from wapitiCore.wappalyzer.wappalyzer import ApplicationData, Wappalyzer
from wapitiCore.net.response import Response


@respx.mock
@pytest.mark.asyncio
async def test_applicationdata():
    categories_file_path = "categories.txt"
    groups_file_path = "groups.txt"
    technologies_file_path = "technologies.txt"

    groups_text = """{
        "9": {
            "name": "Web development"
        },
        "7": {
            "name": "Servers"
        }
    }"""

    categories_text = """{
        "27": {
            "groups": [
                9
            ],
            "name": "Programming languages",
            "priority": 5
        },
        "25": {
            "groups": [
                9
            ],
            "name": "JavaScript graphics",
            "priority": 6
        },
        "31": {
            "groups": [
            7
        ],
        "name": "CDN",
        "priority": 9
        }
    }"""

    technologies_text = """{
        "PHP": {
            "cats": [
                27
            ],
            "cookies": {
                "PHPSESSID": ""
            },
            "cpe": "cpe:/a:php:php",
            "description": "PHP is a general-purpose scripting language used for web development.",
            \"headers\": {\"Server\": \"php/?([\\\\d.]+)?\\\\;version:\\\\1\",\"X-Powered-By\": \"^php/?([\\\\d.]+)?\\\\;version:\\\\1\"},
            "icon": "PHP.svg",
            "url": \"\\\\.php(?:$|\\\\?)\",
            "website": "http://php.net"
        },
        "Akamai": {
            "cats": [
                31
            ],
            "description": "Akamai is global content delivery network (CDN) services provider for media and software delivery, and cloud security solutions.",
            "headers": {
                "X-Akamai-Transformed": "",
                "X-EdgeConnect-MidMile-RTT": "",
                "X-EdgeConnect-Origin-MEX-Latency": ""
            },
            "icon": "Akamai.svg",
            "pricing": [
                "poa"
            ],
            "saas": true,
            "website": "http://akamai.com"
        },
         "A-Frame": {
            "cats": [
            25
            ],
            "html": "<a-scene[^<>]*>",
            "icon": "A-Frame.svg",
            "implies": "three.js",
            "js": {
                \"AFRAME.version\": \"^(.+)$\\\\;version:\\\\1\"
            },
            \"scripts\": \"/?([\\\\d.]+)?/aframe(?:\\\\.min)?\\\\.js\\\\;version:\\\\1\",
            "website": "https://aframe.io"
        }
    }"""

    def get_mock_open(files: Dict[str, str]):
        def open_mock(filename, *args, **kwargs):
            for expected_filename, content in files.items():
                if filename == expected_filename:
                    return mock_open(read_data=content).return_value
            raise FileNotFoundError('(mock) Unable to open {filename}')

        return MagicMock(side_effect=open_mock)

    files = {
        f'{categories_file_path}': categories_text,
        f'{groups_file_path}': groups_text,
        f'{technologies_file_path}': technologies_text,
    }

    with mock.patch("builtins.open", get_mock_open(files)):
        application_data = ApplicationData(categories_file_path, groups_file_path, technologies_file_path)

    assert application_data is not None
    assert len(application_data.get_applications()) == 3
    assert len(application_data.get_categories()) == 3
    assert len(application_data.get_groups()) == 2

    target_url = "http://perdu.com/"

    respx.get(target_url).mock(
        return_value=httpx.Response(
            200,
            text="<html><head><title>Vous Etes Perdu ?</title></head><body><h1>Perdu sur l'Internet ?</h1> \
            <h2>Pas de panique, on va vous aider</h2> \
            <strong><pre>    * <----- vous &ecirc;tes ici</pre></strong></body></html>",
            headers=[
                ('server', 'nginx/1.19.0'),
                ('content-type', 'text/html; charset=UTF-8'),
                ('x-powered-by', 'PHP/5.6.40-38+ubuntu20.04.1+deb.sury.org+1'),
                ('x-akamai-transformed', 'another text value')
            ]
        )
    )

    resp = httpx.get(target_url, follow_redirects=False)
    page = Response(resp)

    wappalyzer = Wappalyzer(application_data, page, {})
    result = wappalyzer.detect()

    # Value based detection result
    assert len(result) == 2
    assert result.get("PHP") is not None
    assert len(result.get("PHP").get("categories")) == 1
    assert result.get("PHP").get("categories")[0] == "Programming languages"
    assert len(result.get("PHP").get("groups")) == 1
    assert result.get("PHP").get("groups")[0] == "Web development"

    # Key based detection result
    assert result.get("Akamai") is not None
    assert len(result.get("Akamai").get("categories")) == 1
    assert result.get("Akamai").get("categories")[0] == "CDN"
    assert len(result.get("Akamai").get("groups")) == 1
    assert result.get("Akamai").get("groups")[0] == "Servers"

    assert result.get("A-Frame") is None
