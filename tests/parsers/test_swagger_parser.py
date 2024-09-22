from wapitiCore.parsers.swagger import Swagger
from wapitiCore.net import Request


def test_swagger_parser_as_url_json():
    url = "http://petstore.swagger.io/v2/swagger.json"
    page = Swagger(url)

    assert {
               "https://petstore.swagger.io/v2/pet",
               "https://petstore.swagger.io/v2/pet/findByStatus?status=available",
               "https://petstore.swagger.io/v2/pet/findByTags?tags=default",
               "https://petstore.swagger.io/v2/pet/1337",
               "https://petstore.swagger.io/v2/pet/1337/uploadImage",
               "https://petstore.swagger.io/v2/store/inventory",
               "https://petstore.swagger.io/v2/store/order",
               "https://petstore.swagger.io/v2/store/order/1337",
               "https://petstore.swagger.io/v2/user",
               "https://petstore.swagger.io/v2/user/createWithArray",
               "https://petstore.swagger.io/v2/user/createWithList",
               "https://petstore.swagger.io/v2/user/logout",
               "https://petstore.swagger.io/v2/user/default",
               "https://petstore.swagger.io/v2/user/login?username=default&password=default"
           } == {x.url for x in page.get_requests()}


def test_swagger_parser_as_url_yaml():
    url = "http://petstore.swagger.io/v2/swagger.yaml"
    page = Swagger(url)

    assert {
               "https://petstore.swagger.io/v2/pet",
               "https://petstore.swagger.io/v2/pet/findByStatus?status=available",
               "https://petstore.swagger.io/v2/pet/findByTags?tags=default",
               "https://petstore.swagger.io/v2/pet/1337",
               "https://petstore.swagger.io/v2/pet/1337/uploadImage",
               "https://petstore.swagger.io/v2/store/inventory",
               "https://petstore.swagger.io/v2/store/order",
               "https://petstore.swagger.io/v2/store/order/1337",
               "https://petstore.swagger.io/v2/user",
               "https://petstore.swagger.io/v2/user/createWithArray",
               "https://petstore.swagger.io/v2/user/createWithList",
               "https://petstore.swagger.io/v2/user/logout",
               "https://petstore.swagger.io/v2/user/default",
               "https://petstore.swagger.io/v2/user/login?username=default&password=default"
           } == {x.url for x in page.get_requests()}


def test_swagger_parser_as_file():
    url = "tests/data/swagger.json"
    page = Swagger(url)

    assert {
               "https://petstore.swagger.io/v2/pet",
               "https://petstore.swagger.io/v2/pet/findByStatus?status=available",
               "https://petstore.swagger.io/v2/pet/findByTags?tags=default",
               "https://petstore.swagger.io/v2/pet/1337",
               "https://petstore.swagger.io/v2/pet/1337/uploadImage",
               "https://petstore.swagger.io/v2/store/inventory",
               "https://petstore.swagger.io/v2/store/order",
               "https://petstore.swagger.io/v2/store/order/1337",
               "https://petstore.swagger.io/v2/user",
               "https://petstore.swagger.io/v2/user/createWithArray",
               "https://petstore.swagger.io/v2/user/createWithList",
               "https://petstore.swagger.io/v2/user/logout",
               "https://petstore.swagger.io/v2/user/default",
               "https://petstore.swagger.io/v2/user/login?username=default&password=default",
               'https://petstore.swagger.io/v2/v1.0/default/flavors&belongsTo=default'
           } == {x.url for x in page.get_requests()}


def test_swagger_file_complexe():
    url = "tests/data/complexe_swagger.json"
    page = Swagger(url)

    request_header = Request("https://fakeSwagger.fr/api/v2.0/projects?project_name=default", "HEAD", post_params="",
                             file_params=[])
    request_header.set_headers({'X-Request-Id': 'default'})

    request_get = Request("https://fakeSwagger.fr/api/v2.0/labels/1337", "GET", post_params="", file_params=[])
    request_get.set_headers({'X-Request-Id': 'default'})

    params = '{"name": "default", "description": "default", "expires_at": "1337", "access": [{"resource": "default", "action": "default", "effect": "default"}]}'
    request_post = Request("https://fakeSwagger.fr/api/v2.0/projects/default/robots", "POST", post_params=params,
                           file_params=[], enctype="application/json")
    request_post.set_headers({'X-Request-Id': 'default'})

    request_delete = Request("https://fakeSwagger.fr/api/v2.0/users/1337", "DELETE", post_params="", file_params=[])
    request_delete.set_headers({'X-Request-Id': 'default'})

    params = '{"id": "1337", "name": "default", "description": "default", "color": "default", "scope": "default", "project_id": "1337", "creation_time": "2024-08-16T16:03:08", "update_time": "2024-08-16T16:03:08"}'
    request_put = Request("https://fakeSwagger.fr/api/v2.0/labels/1337", "PUT", post_params=params, file_params=[],
                          enctype="application/json")
    request_put.set_headers({'X-Request-Id': 'default'})

    params = '{"id": "1337", "vendor_type": "default", "vendor_id": "1337", "status": "default", "status_message": "default", "metrics": {"task_count": "1337", "success_task_count": "1337", "error_task_count": "1337", "pending_task_count": "1337", "running_task_count": "1337", "scheduled_task_count": "1337", "stopped_task_count": "1337"}, "trigger": "default", "extra_attrs": {}, "start_time": "default", "end_time": "default"}'
    request_patch = Request("https://fakeSwagger.fr/api/v2.0/projects/default/preheat/policies/default/executions/1337",
                            "PATCH", post_params=params, file_params=[], enctype="application/json")
    request_patch.set_headers({'X-Request-Id': 'default'})

    list_request = [request_header, request_get, request_post, request_delete, request_put, request_patch]
    requests = page.get_requests()

    for item in list_request:
        assert item in requests


def test_swagger_file_yaml():
    url = "tests/data/swagger.yaml"
    page = Swagger(url)

    assert {
               "https://petstore.swagger.io/v2/pet",
               "https://petstore.swagger.io/v2/pet/findByStatus?status=available",
               "https://petstore.swagger.io/v2/pet/findByTags?tags=default",
               "https://petstore.swagger.io/v2/pet/1337",
               "https://petstore.swagger.io/v2/pet/1337/uploadImage",
               "https://petstore.swagger.io/v2/store/inventory",
               "https://petstore.swagger.io/v2/store/order",
               "https://petstore.swagger.io/v2/store/order/1337",
               "https://petstore.swagger.io/v2/user",
               "https://petstore.swagger.io/v2/user/createWithArray",
               "https://petstore.swagger.io/v2/user/createWithList",
               "https://petstore.swagger.io/v2/user/logout",
               "https://petstore.swagger.io/v2/user/default",
               "https://petstore.swagger.io/v2/user/login?username=default&password=default"
           } == {x.url for x in page.get_requests()}


def test_openapi_file():
    url = "tests/data/openapi.json"
    page = Swagger(base_url="https://fake.openapi.fr", swagger_url=url)

    request_get = Request("https://fake.openapi.fr/v1/AdministrationSettings/GroupUsers", "GET", post_params="",
                          file_params=[])

    request_post = Request("https://fake.openapi.fr/v1/AdministrationSettings/GroupUsers?userId=default", "POST",
                           post_params="", file_params=[])

    request_delete = Request("https://fake.openapi.fr/v1/AdministrationSettings/MailAccount?id=1337", "DELETE",
                             post_params="", file_params=[])

    params = '{"alarmState": "default", "confirmingUserName": "default", "confirmingDateTime": "2024-08-16T16:03:08", "confirmingNote": "default"}'
    request_put = Request("https://fake.openapi.fr/v1/Alarms/1337", "PUT", post_params=params, file_params=[],
                          enctype="application/json")

    params = '{"active": true, "userName": "default", "emailAddress": "default", "role": "1337", "networksVisibility": true}'
    request_put2 = Request("https://fake.openapi.fr/v1/AdministrationSettings/GroupUsers", "PUT", post_params=params,
                           file_params=[], enctype="application/json")

    params = '{"active": true, "userName": "default", "emailAddress": "default", "role": "1337", "networksVisibility": true}'
    request_patch = Request("https://fake.openapi.fr/v1/AdministrationSettings/GroupUsers", "PATCH", post_params=params,
                            file_params=[], enctype="application/json")

    list_request = [request_get, request_post, request_delete, request_patch, request_put, request_put2]
    requests = page.get_requests()

    for item in list_request:
        assert item in requests


def test_openapi_yaml_file():
    url = "tests/data/openapi.yaml"
    page = Swagger(base_url="https://fake.openapi.fr", swagger_url=url)

    assert {
               "https://fake.openapi.fr/",
               "https://fake.openapi.fr/eval?s=default",
               "https://fake.openapi.fr/help"
           } == {x.url for x in page.get_requests()}


def test_openapi3():
    url = "tests/data/openapi3.yaml"
    page = Swagger(base_url="https://fake.openapi.fr", swagger_url=url)

    assert {
               "https://fake.openapi.fr:8080/v1/pets?limit=1337",
               "https://fake.openapi.fr:8080/v1/pets",
               "https://fake.openapi.fr:8080/v1/pets/default"
           } == {x.url for x in page.get_requests()}
