from pathlib import Path

import pytest

from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.parsers.swagger import Swagger
from wapitiCore.net import Request


@pytest.mark.asyncio
async def test_swagger_urlencoded():
    swagger_path = Path(__file__).parent / "data" / "urlencoded.yaml"
    crawler_configuration = CrawlerConfiguration(Request("https://petstore.swagger.io/"), timeout=1)
    swagger = Swagger(
        swagger_url=str(swagger_path),
        base_url="https://petstore.swagger.io/",
        crawler_configuration=crawler_configuration
    )

    requests = await swagger.get_requests()
    assert len(requests) == 1
    login_request = requests[0]

    assert login_request.post_params == [['username', 'default'], ['password', 'Letm3in_']]
    assert login_request.enctype == "application/x-www-form-urlencoded"


@pytest.mark.asyncio
async def test_swagger_urlencoded():
    swagger_path = Path(__file__).parent / "data" / "swagger.json"
    crawler_configuration = CrawlerConfiguration(Request("https://petstore.swagger.io/"), timeout=1)
    swagger = Swagger(
        swagger_url=str(swagger_path),
        base_url="https://petstore.swagger.io/",
        crawler_configuration=crawler_configuration
    )

    requests = await swagger.get_requests()
    upload_request = requests[0]

    assert upload_request.url == "https://petstore.swagger.io/v2/pet/1/uploadImage"
    assert upload_request.file_params == [['file', ('pix.gif', b'GIF89a', 'image/gif')]]
    assert upload_request.post_params == [['additionalMetadata', 'default']]
    assert upload_request.enctype == "multipart/form-data"


@pytest.mark.asyncio
async def test_swagger_json_enctype():
    swagger_path = Path(__file__).parent / "data" / "openapi.json"
    crawler_configuration = CrawlerConfiguration(Request("https://petstore.swagger.io/"), timeout=1)
    swagger = Swagger(
        swagger_url=str(swagger_path),
        base_url="https://fake.openapi.fr/",
        crawler_configuration=crawler_configuration
    )

    requests = await swagger.get_requests()
    put_alarm = requests[0]

    assert put_alarm.method == "PUT"
    assert put_alarm.url == "https://fake.openapi.fr/v1/Alarms/1"
    assert put_alarm.enctype == "application/json"
