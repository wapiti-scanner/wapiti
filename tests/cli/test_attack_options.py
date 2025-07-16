import pytest
from argparse import Namespace

from wapitiCore.controller.exceptions import InvalidOptionValue
from wapitiCore.main.wapiti import build_attack_options_from_args


@pytest.mark.parametrize(
    "args,expected_keys",
    [
        (
            Namespace(
                level=2,
                timeout=10,
                tasks=5,
                headless=True,
                excluded_urls=["http://example.com/logout"],
                max_attack_time=60,
                update=False,
                wapp_url=None,
                wapp_dir=None,
                cms=None,
                modules=[],
                skipped_parameters=[]
            ),
            {"level", "timeout", "tasks", "headless", "excluded_urls", "max_attack_time"}
        ),
        (
            Namespace(
                level=1,
                timeout=5,
                tasks=2,
                headless=False,
                excluded_urls=[],
                max_attack_time=120,
                update=True,
                wapp_url=None,
                wapp_dir=None,
                cms=None,
                modules=[],
                skipped_parameters=[]
            ),
            {"level", "timeout", "tasks", "headless", "excluded_urls", "max_attack_time", "wapp_url"}
        ),
        (
            Namespace(
                level=3,
                timeout=15,
                tasks=10,
                headless=True,
                excluded_urls=[],
                max_attack_time=200,
                update=False,
                wapp_url="https://wapp.example.com/",
                wapp_dir=None,
                cms="wp",
                modules=["cms", "wapp"],
                skipped_parameters=["debug"]
            ),
            {
                "level", "timeout", "tasks", "headless", "excluded_urls", "max_attack_time", "wapp_url", "cms",
                "skipped_parameters"
            }
        ),
        (
                Namespace(
                    level=1,
                    timeout=5,
                    tasks=1,
                    headless=False,
                    excluded_urls=[],
                    max_attack_time=30,
                    update=False,
                    wapp_url=None, wapp_dir=None, cms=None, modules=[], skipped_parameters=[],
                    dns_endpoint="http://dns.example.com/",
                    endpoint="http://http.example.com/",
                ),
                {
                    "level", "timeout", "tasks", "headless", "excluded_urls", "max_attack_time",
                    "dns_endpoint", "internal_endpoint", "external_endpoint"
                }
        )
    ]
)
def test_build_attack_options_success(args, expected_keys):
    opts = build_attack_options_from_args(args)
    assert isinstance(opts, dict)
    for key in expected_keys:
        assert key in opts


def test_invalid_cms_raises():
    args = Namespace(
        level=1,
        timeout=5,
        tasks=1,
        headless=False,
        excluded_urls=[],
        max_attack_time=30,
        update=False,
        cms="unknowncms",
        modules=["cms"],
        wapp_url=None,
        wapp_dir=None,
        skipped_parameters=[]
    )
    with pytest.raises(InvalidOptionValue) as exc_info:
        build_attack_options_from_args(args)
    assert "--cms" in str(exc_info.value)


def test_invalid_wapp_dir_raises(tmp_path):
    invalid_path = tmp_path / "nonexistent_dir"
    args = Namespace(
        level=1,
        timeout=5,
        tasks=1,
        headless=False,
        excluded_urls=[],
        max_attack_time=30,
        update=False,
        wapp_url=None,
        wapp_dir=str(invalid_path),
        cms=None,
        modules=["wapp"],
        skipped_parameters=[]
    )
    with pytest.raises(InvalidOptionValue) as exc_info:
        build_attack_options_from_args(args)
    assert "--wapp-dir" in str(exc_info.value)


def test_build_attack_options_with_invalid_external_endpoint_raises():
    """Case where '--external-endpoint' is not valid."""
    args = Namespace(
        level=1, timeout=5, tasks=1, headless=False, excluded_urls=[], max_attack_time=30,
        update=False, wapp_url=None, wapp_dir=None, cms=None, modules=[], skipped_parameters=[],
        dns_endpoint=None, external_endpoint="ftp://invalid.external/",
    )
    with pytest.raises(InvalidOptionValue) as exc_info:
        build_attack_options_from_args(args)
    assert "--external-endpoint" in str(exc_info.value)


def test_build_attack_options_with_internal_endpoint_not_accessible_raises():
    """Case where '--internal-endpoint' is valid but can't be joined."""
    args = Namespace(
        level=1, timeout=5, tasks=1, headless=False, excluded_urls=[], max_attack_time=30,
        update=False, wapp_url=None, wapp_dir=None, cms=None, modules=[], skipped_parameters=[],
        dns_endpoint=None, internal_endpoint="http://192.0.2.1/private/", # TEST-NET-1, non routable
    )
    with pytest.raises(InvalidOptionValue) as exc_info:
        build_attack_options_from_args(args)
        assert "--internal-endpoint" in str(exc_info.value)
        assert "Invalid argument for option --internal-endpoint : http://192.0.2.1/private/" in str(exc_info.value)

