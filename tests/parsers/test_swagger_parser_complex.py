from pathlib import Path

import pytest

from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.parsers.swagger import Swagger
from wapitiCore.net import Request


@pytest.mark.asyncio
async def test_swagger_file_complex():
    swagger_path = Path(__file__).parent / "data" / "complex_swagger.json"
    crawler_configuration = CrawlerConfiguration(Request("https://fakeSwagger.fr/"), timeout=1)
    swagger = Swagger(
        swagger_url=str(swagger_path),
        base_url="https://fakeSwagger.fr/",
        crawler_configuration=crawler_configuration,
    )

    expected_requests = []
    for url in [
        "https://fakeSwagger.fr/api/v2.0/labels/1",
        "https://fakeSwagger.fr/api/v2.0/projects/1",
        "https://fakeSwagger.fr/api/v2.0/projects/default/preheat/policies/default",
        "https://fakeSwagger.fr/api/v2.0/users/1",
    ]:
        expected_requests.append(
            Request(url, "DELETE")
        )

    for url in [
        'https://fakeSwagger.fr/api/v2.0/labels/1',
        'https://fakeSwagger.fr/api/v2.0/projects/1',
        'https://fakeSwagger.fr/api/v2.0/projects/1/metadatas/',
        'https://fakeSwagger.fr/api/v2.0/projects/1/robots?page=1&page_size=10&q=default&sort=default',
        'https://fakeSwagger.fr/api/v2.0/projects/default/preheat/policies/default',
        'https://fakeSwagger.fr/api/v2.0/projects/default/preheat/policies/default/executions/1',
        'https://fakeSwagger.fr/api/v2.0/projects/default/repositories/default/artifacts?q=default&sort=default&page=1&page_size=10&with_tag=true&with_label=false&with_scan_overview=false&with_signature=false&with_immutable_status=false&with_accessory=false',
        'https://fakeSwagger.fr/api/v2.0/projects?q=default&page=1&page_size=10&sort=default&name=default&public=true&owner=default&with_detail=true',
        'https://fakeSwagger.fr/api/v2.0/scanners?q=default&sort=default&page=1&page_size=10',
        'https://fakeSwagger.fr/api/v2.0/system/CVEAllowlist',
        'https://fakeSwagger.fr/api/v2.0/system/purgeaudit/schedule',
        'https://fakeSwagger.fr/api/v2.0/system/scanAll/schedule',
        'https://fakeSwagger.fr/api/v2.0/users/1',
        'https://fakeSwagger.fr/api/v2.0/users?q=default&sort=default&page=1&page_size=10'
    ]:
        expected_requests.append(
            Request(url, "GET")
        )

    expected_requests.extend(
        [
            Request(
                "https://fakeSwagger.fr/api/v2.0/projects?project_name=default",
                "HEAD",
            ),
            Request(
                "https://fakeSwagger.fr/api/v2.0/projects/default/preheat/policies/default/executions/1",
                "PATCH",
                post_params=(
                    '{"id": 1, "vendor_type": "default", "vendor_id": 1, "status": "default", '
                    '"status_message": "default", "metrics": {"task_count": 1, "success_task_count": 1, '
                    '"error_task_count": 1, "pending_task_count": 1, "running_task_count": 1, '
                    '"scheduled_task_count": 1, "stopped_task_count": 1}, "trigger": "default", "extra_attrs": {}, '
                    '"start_time": "default", "end_time": "default"}'
                ),
                enctype="application/json"
            )
        ]
    )

    for post_url, post_data in {
        "https://fakeSwagger.fr/api/v2.0/export/cve": (
                '{"job_name": "default", "projects": [1], "labels": [1], "repositories": "default", '
                '"cveIds": "default", "tags": "default"}'
        ),
        "https://fakeSwagger.fr/api/v2.0/ldap/users/import": '{"ldap_uid_list": ["default"]}',
        "https://fakeSwagger.fr/api/v2.0/projects": (
            '{"project_name": "default", "public": true, "metadata": {"public": "default", '
            '"enable_content_trust": "default", "enable_content_trust_cosign": "default", "prevent_vul": "default", '
            '"severity": "default", "auto_scan": "default", "reuse_sys_cve_allowlist": "default", '
            '"retention_id": "default"}, "cve_allowlist": {"id": 1, "project_id": 1, "expires_at": 1, '
            '"items": [{"cve_id": "default"}], "creation_time": "2023-03-03T20:35:34.32", '
            '"update_time": "2023-03-03T20:35:34.32"}, "storage_limit": 1, "registry_id": 1}'
        ),
        "https://fakeSwagger.fr/api/v2.0/projects/1/metadatas/": '{}',
        "https://fakeSwagger.fr/api/v2.0/projects/1/robots": (
            '{"name": "default", "description": "default", "expires_at": 1, "access": [{"resource": "default", '
            '"action": "default", "effect": "default"}]}'
        ),
        "https://fakeSwagger.fr/api/v2.0/projects/default/preheat/policies/default": (
                '{"id": 1, "name": "default", "description": "default", "project_id": 1, "provider_id": 1, '
                '"provider_name": "default", "filters": "default", "trigger": "default", "enabled": true, '
                '"creation_time": "2023-03-03T20:35:34.32", "update_time": "2023-03-03T20:35:34.32"}'
        ),
        "https://fakeSwagger.fr/api/v2.0/projects/default/repositories/default/artifacts?from=default": None,
        "https://fakeSwagger.fr/api/v2.0/scanners": (
            '{"name": "default", "description": "default", "url": "https://example.com/api", "auth": "default", '
            '"access_credential": "default", "skip_certVerify": false, "use_internal_addr": false, "disabled": false}'
        ),
        "https://fakeSwagger.fr/api/v2.0/system/purgeaudit/schedule": (
            '{"id": 1, "status": "default", "creation_time": "2023-03-03T20:35:34.32", '
            '"update_time": "2023-03-03T20:35:34.32", "schedule": {"type": "Hourly", "cron": "default", '
            '"next_scheduled_time": "2023-03-03T20:35:34.32"}, "parameters": {}}'
        ),
        "https://fakeSwagger.fr/api/v2.0/system/scanAll/schedule": (
                '{"id": 1, "status": "default", "creation_time": "2023-03-03T20:35:34.32", '
                '"update_time": "2023-03-03T20:35:34.32", "schedule": {"type": "Hourly", "cron": "default", '
                '"next_scheduled_time": "2023-03-03T20:35:34.32"}, "parameters": {}}'
        ),
        "https://fakeSwagger.fr/api/v2.0/users": (
	        '{"email": "default", "realname": "default", "comment": "default", "password": "default", '
            '"username": "default"}'
        )
    }.items():
        expected_requests.append(
            Request(
                post_url,
                "POST",
                post_params=post_data,
                enctype="application/json"
            )
        )

    for put_url, put_data in {
         "https://fakeSwagger.fr/api/v2.0/labels/1": (
             '{"id": 1, "name": "default", "description": "default", "color": "default", "scope": "default", '
             '"project_id": 1, "creation_time": "2023-03-03T20:35:34.32", "update_time": "2023-03-03T20:35:34.32"}'
         ),
        "https://fakeSwagger.fr/api/v2.0/projects/1": (
            '{"project_name": "default", "public": true, "metadata": {"public": "default", '
            '"enable_content_trust": "default", "enable_content_trust_cosign": "default", "prevent_vul": "default", '
            '"severity": "default", "auto_scan": "default", "reuse_sys_cve_allowlist": "default", "retention_id": '
            '"default"}, "cve_allowlist": {"id": 1, "project_id": 1, "expires_at": 1, '
            '"items": [{"cve_id": "default"}], "creation_time": "2023-03-03T20:35:34.32", '
            '"update_time": "2023-03-03T20:35:34.32"}, "storage_limit": 1, "registry_id": 1}'
        ),
        "https://fakeSwagger.fr/api/v2.0/projects/default/preheat/policies/default": (
            '{"id": 1, "name": "default", "description": "default", "project_id": 1, "provider_id": 1, '
            '"provider_name": "default", "filters": "default", "trigger": "default", "enabled": true, '
            '"creation_time": "2023-03-03T20:35:34.32", "update_time": "2023-03-03T20:35:34.32"}'
        ),
        "https://fakeSwagger.fr/api/v2.0/system/CVEAllowlist": (
            '{"id": 1, "project_id": 1, "expires_at": 1, "items": [{"cve_id": "default"}], '
            '"creation_time": "2023-03-03T20:35:34.32", "update_time": "2023-03-03T20:35:34.32"}'
        ),
        "https://fakeSwagger.fr/api/v2.0/system/purgeaudit/schedule": (
	        '{"id": 1, "status": "default", "creation_time": "2023-03-03T20:35:34.32", '
            '"update_time": "2023-03-03T20:35:34.32", "schedule": {"type": "Hourly", "cron": "default", '
            '"next_scheduled_time": "2023-03-03T20:35:34.32"}, "parameters": {}}'
        ),
        "https://fakeSwagger.fr/api/v2.0/system/scanAll/schedule": (
	        '{"id": 1, "status": "default", "creation_time": "2023-03-03T20:35:34.32", '
            '"update_time": "2023-03-03T20:35:34.32", "schedule": {"type": "Hourly", "cron": "default", '
            '"next_scheduled_time": "2023-03-03T20:35:34.32"}, "parameters": {}}'
        ),
        "https://fakeSwagger.fr/api/v2.0/users/1": (
	        '{"email": "default", "realname": "default", "comment": "default"}'
        )
    }.items():
        expected_requests.append(
            Request(
                put_url,
                "PUT",
                post_params=put_data,
                enctype="application/json"
            )
        )

    # request_header.set_headers({'X-Request-Id': 'default'})

    obtained_requests = sorted(
        await swagger.get_requests(),
        key=lambda req: req.method + req.path + req.encoded_get_keys
    )

    assert obtained_requests == expected_requests
