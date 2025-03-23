from pathlib import Path

import pytest

import httpx
import respx

from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.parsers.swagger import Swagger
from wapitiCore.net import Request


@pytest.mark.asyncio
@respx.mock
async def test_swagger_parser_as_url_json():
    url = "http://petstore.swagger.io/v2/swagger.json"
    crawler_configuration = CrawlerConfiguration(Request("https://petstore.swagger.io/"), timeout=1)
    swagger = Swagger(
        swagger_url=url,
        base_url="https://petstore.swagger.io/",
        crawler_configuration=crawler_configuration
    )

    test_path = Path(__file__).parent / "data" / "petstore_20250320.json"
    with test_path.open(encoding="utf-8") as file_obj:
        respx.get(url).mock(return_value=httpx.Response(200, text=file_obj.read()))

    assert {
               "https://petstore.swagger.io/v2/pet",
               "https://petstore.swagger.io/v2/pet/findByStatus?status=available",
               "https://petstore.swagger.io/v2/pet/findByTags?tags=default",
               "https://petstore.swagger.io/v2/pet/1",
               "https://petstore.swagger.io/v2/pet/1/uploadImage",
               "https://petstore.swagger.io/v2/store/inventory",
               "https://petstore.swagger.io/v2/store/order",
               "https://petstore.swagger.io/v2/store/order/1",
               "https://petstore.swagger.io/v2/user",
               "https://petstore.swagger.io/v2/user/createWithArray",
               "https://petstore.swagger.io/v2/user/createWithList",
               "https://petstore.swagger.io/v2/user/logout",
               "https://petstore.swagger.io/v2/user/alice",
               "https://petstore.swagger.io/v2/user/login?username=alice&password=Letm3in_"
           } == {x.url for x in await swagger.get_requests()}


@pytest.mark.asyncio
@respx.mock
async def test_swagger_parser_as_url_yaml():
    url = "http://petstore.swagger.io/v2/swagger.yaml"
    crawler_configuration = CrawlerConfiguration(Request("https://petstore.swagger.io/"), timeout=1)
    swagger = Swagger(
        swagger_url=url,
        base_url="https://petstore.swagger.io/",
        crawler_configuration=crawler_configuration
    )

    test_path = Path(__file__).parent / "data" / "petstore_20250320.yaml"
    with test_path.open(encoding="utf-8") as file_obj:
        respx.get(url).mock(return_value=httpx.Response(200, text=file_obj.read()))

    assert {
               "https://petstore.swagger.io/v2/pet",
               "https://petstore.swagger.io/v2/pet/findByStatus?status=available",
               "https://petstore.swagger.io/v2/pet/findByTags?tags=default",
               "https://petstore.swagger.io/v2/pet/1",
               "https://petstore.swagger.io/v2/pet/1/uploadImage",
               "https://petstore.swagger.io/v2/store/inventory",
               "https://petstore.swagger.io/v2/store/order",
               "https://petstore.swagger.io/v2/store/order/1",
               "https://petstore.swagger.io/v2/user",
               "https://petstore.swagger.io/v2/user/createWithArray",
               "https://petstore.swagger.io/v2/user/createWithList",
               "https://petstore.swagger.io/v2/user/logout",
               "https://petstore.swagger.io/v2/user/alice",
               "https://petstore.swagger.io/v2/user/login?username=alice&password=Letm3in_"
           } == {x.url for x in await swagger.get_requests()}


@pytest.mark.asyncio
async def test_swagger_parser_as_file():
    swagger_path = Path(__file__).parent / "data" / "swagger.json"
    crawler_configuration = CrawlerConfiguration(Request("https://petstore.swagger.io/"), timeout=1)
    swagger = Swagger(
        swagger_url=str(swagger_path),
        base_url="https://petstore.swagger.io/",
        crawler_configuration=crawler_configuration
    )

    assert {
               "https://petstore.swagger.io/v2/pet",
               "https://petstore.swagger.io/v2/pet/findByStatus?status=available",
               "https://petstore.swagger.io/v2/pet/findByTags?tags=default",
               "https://petstore.swagger.io/v2/pet/1",
               "https://petstore.swagger.io/v2/pet/1/uploadImage",
               "https://petstore.swagger.io/v2/store/inventory",
               "https://petstore.swagger.io/v2/store/order",
               "https://petstore.swagger.io/v2/store/order/1",
               "https://petstore.swagger.io/v2/user",
               "https://petstore.swagger.io/v2/user/createWithArray",
               "https://petstore.swagger.io/v2/user/createWithList",
               "https://petstore.swagger.io/v2/user/logout",
               "https://petstore.swagger.io/v2/user/alice",
               "https://petstore.swagger.io/v2/user/login?username=alice&password=Letm3in_",
               'https://petstore.swagger.io/v2/v1.0/1/flavors?belongsTo=default'
           } == {x.url for x in await swagger.get_requests()}

    for request in await swagger.get_requests():
        if request.path == "https://petstore.swagger.io/v2/pet/1/uploadImage":
            assert request.post_params == [['additionalMetadata', 'default']]
            assert request.file_params == [['file', ('pix.gif', b'GIF89a', 'image/gif')]]


@pytest.mark.asyncio
async def test_swagger_file_yaml():
    swagger_path = Path(__file__).parent / "data" / "swagger.yaml"
    crawler_configuration = CrawlerConfiguration(Request("https://petstore.swagger.io/"), timeout=1)
    swagger = Swagger(
        swagger_url=str(swagger_path),
        base_url="https://petstore.swagger.io/",
        crawler_configuration=crawler_configuration,
    )

    assert {
               "https://petstore.swagger.io/v2/pet",
               "https://petstore.swagger.io/v2/pet/findByStatus?status=available",
               "https://petstore.swagger.io/v2/pet/findByTags?tags=default",
               "https://petstore.swagger.io/v2/pet/1",
               "https://petstore.swagger.io/v2/pet/1/uploadImage",
               "https://petstore.swagger.io/v2/store/inventory",
               "https://petstore.swagger.io/v2/store/order",
               "https://petstore.swagger.io/v2/store/order/1",
               "https://petstore.swagger.io/v2/user",
               "https://petstore.swagger.io/v2/user/createWithArray",
               "https://petstore.swagger.io/v2/user/createWithList",
               "https://petstore.swagger.io/v2/user/logout",
               "https://petstore.swagger.io/v2/user/alice",
               "https://petstore.swagger.io/v2/user/login?username=alice&password=Letm3in_"
           } == {x.url for x in await swagger.get_requests()}


@pytest.mark.asyncio
async def test_openapi_file():
    swagger_path = Path(__file__).parent / "data" / "openapi.json"
    crawler_configuration = CrawlerConfiguration(Request("https://petstore.swagger.io/"), timeout=1)
    swagger = Swagger(
        base_url="https://fake.openapi.fr",
        swagger_url=str(swagger_path),
        crawler_configuration=crawler_configuration,
    )

    request_delete = Request(
        "https://fake.openapi.fr/v1/AdministrationSettings/MailAccount?id=1",
        "DELETE",
        post_params="",
        file_params=[]
    )

    request_get = Request(
        "https://fake.openapi.fr/v1/AdministrationSettings/GroupUsers",
        "GET",
        post_params="",
        file_params=[]
    )

    params = '{"active": true, "userName": "default", "emailAddress": "default", "role": 1, "networksVisibility": {}}'
    request_patch = Request(
        "https://fake.openapi.fr/v1/AdministrationSettings/GroupUsers",
        "PATCH",
        post_params=params,
        file_params=[],
        enctype="application/json")

    request_post = Request(
        "https://fake.openapi.fr/v1/AdministrationSettings/GroupUsers?userId=1",
        "POST",
        post_params="",
        file_params=[]
    )

    params = '[{"active": true, "userName": "default", "emailAddress": "default", "role": 1, "networksVisibility": {}}]'
    request_put1 = Request(
        "https://fake.openapi.fr/v1/AdministrationSettings/GroupUsers",
        "PUT",
        post_params=params,
        file_params=[],
        enctype="application/json"
    )

    params = '{"alarmState": "default", "confirmingUserName": "default", "confirmingDateTime": "2023-03-03T20:35:34.32", "confirmingNote": "default"}'
    request_put2 = Request(
        "https://fake.openapi.fr/v1/Alarms/1",
        "PUT",
        post_params=params,
        file_params=[],
        enctype="application/json"
    )

    expected_requests = [request_delete, request_get, request_patch, request_post, request_put1, request_put2]
    obtained_requests = sorted(
        await swagger.get_requests(),
        key=lambda req: req.method + req.path + req.encoded_get_keys
    )

    assert expected_requests == obtained_requests


@pytest.mark.asyncio
async def test_openapi_yaml_file():
    swagger_path = Path(__file__).parent / "data" / "openapi.yaml"
    crawler_configuration = CrawlerConfiguration(Request("https://fake.openapi.fr"), timeout=1)
    swagger = Swagger(
        base_url="https://fake.openapi.fr",
        swagger_url=str(swagger_path),
        crawler_configuration=crawler_configuration
    )

    assert {
               "https://fake.openapi.fr/",
               "https://fake.openapi.fr/eval?s=default",
               "https://fake.openapi.fr/help"
           } == {x.url for x in await swagger.get_requests()}


@pytest.mark.asyncio
async def test_openapi3():
    swagger_path = Path(__file__).parent / "data" / "openapi3.yaml"
    crawler_configuration = CrawlerConfiguration(Request("https://fake.openapi.fr"), timeout=1)
    swagger = Swagger(
        base_url="https://fake.openapi.fr",
        swagger_url=str(swagger_path),
        crawler_configuration=crawler_configuration
    )

    assert {
               "https://fake.openapi.fr:8080/v1/pets?limit=1",
               "https://fake.openapi.fr:8080/v1/pets",
               "https://fake.openapi.fr:8080/v1/pets/1"
           } == {x.url for x in await swagger.get_requests()}
