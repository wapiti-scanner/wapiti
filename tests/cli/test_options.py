import sys
from pathlib import Path
from time import monotonic
from unittest import mock

import respx
from httpcore import URL
import httpx
import pytest

from wapitiCore.attack.modules.core import all_modules
from wapitiCore.net import Request, Response
from wapitiCore.main.wapiti import wapiti_main
from wapitiCore.controller.wapiti import Wapiti, InvalidOptionValue


@pytest.mark.asyncio
@mock.patch("wapitiCore.main.wapiti.Wapiti.write_report")
async def test_max_attack_time(_):

    max_attack_time = 10
    delta = 0.1 # max-attack-time percentage

    class CustomMock:
        CONFIG_DIR = ""

        def __init__(self):
            pass

        async def count_paths(self):
            return 0

        async def count_attacked(self, _name):
            return 0

        async def set_attacked(self, path_ids, module_name):
            return

        async def add_payload(self, request_id, payload_type, module,
            category = None, level = 0, request = None, parameter = "",
            info = "", wstg = None, response = None):
            return

        async def get_links(self, attack_module):
            request = Request("http://perdu.com/test/config/")
            request.path_id = 0
            response = Response(
                httpx.Response(
                    status_code=200,
                    headers={"content-type": "text/html"},
                ),
                url="http://perdu.com/test/config/"
            )
            yield request, response

        async def get_forms(self, attack_module):
            request = Request("http://perdu.com/test/config/", "POST")
            request.path_id = 0
            response = Response(
                httpx.Response(
                    status_code=200,
                    headers={"content-type": "text/html"},
                ),
                url="http://perdu.com/test/config/"
            )
            yield request, response

        async def get_root_url(self):
            return "http://perdu.com/"

    with mock.patch("os.makedirs", return_value=True):
        cli = Wapiti(Request("http://perdu.com/"), session_dir="/dev/shm")
        cli.persister = CustomMock()
        cli._active_scanner.persister = CustomMock()
        cli.active_scanner.set_max_attack_time(max_attack_time)
        cli.active_scanner.set_attack_options({"timeout": 10, "tasks": 1})

        cli.active_scanner.set_modules("all")
        time = monotonic()
        await cli.active_scanner.attack()
        max_run_duration = max_attack_time * (len(all_modules) + delta) # execution time for all modules + delta of uncertainty
        assert monotonic() - time < max_run_duration


@pytest.mark.asyncio
@mock.patch("wapitiCore.attack.active_scanner.ActiveScanner.update")
async def test_update_with_modules(mock_update):
    testargs = ["wapiti", "--update", "-m", "wapp,nikto"]
    with mock.patch.object(sys, 'argv', testargs):
        with pytest.raises(SystemExit):
            await wapiti_main()
            mock_update.assert_called_once_with("wapp,nikto")


@pytest.mark.asyncio
@mock.patch("wapitiCore.main.wapiti.is_valid_url")
async def test_update_with_not_valid_url(mock_valid_url):
    testargs = ["wapiti", "--update", "-m", "wapp", "--wapp-url", "htp:/perdu"]
    with mock.patch.object(sys, 'argv', testargs):
        with pytest.raises(SystemExit) as ve:
            await wapiti_main()
            mock_valid_url.assert_called_once_with("htp:/perdu")


@pytest.mark.asyncio
@mock.patch("wapitiCore.attack.active_scanner.ActiveScanner.update")
async def test_update_without_modules(mock_update):
    """Ensure that no module should be updated when no module is requested."""
    testargs = ["wapiti", "--update"]
    with mock.patch.object(sys, 'argv', testargs):
        with pytest.raises(SystemExit):
            await wapiti_main()
            mock_update.assert_called_once_with(None)

@pytest.mark.asyncio
@mock.patch("wapitiCore.attack.active_scanner.ActiveScanner.update")
async def test_update_with_wapp_url(mock_update):
    """Ensure that no module should be updated when no module is requested."""
    testargs = ["wapiti", "--update", "-m", "wapp", "--wapp-url", "https://raw.githubusercontent.com/wapiti-scanner/wappalyzerfork/main/"]
    with mock.patch.object(sys, 'argv', testargs):
        with pytest.raises(SystemExit):
            await wapiti_main()
            mock_update.assert_called_once_with(None)

@pytest.mark.asyncio
@mock.patch("wapitiCore.attack.active_scanner.ActiveScanner.update")
async def test_update_with_wapp_dir(mock_update):
    """Ensure that no module should be updated when no module is requested."""
    testargs = ["wapiti", "--update", "-m", "wapp", "--wapp-dir", "/"]
    with mock.patch.object(sys, 'argv', testargs):
        with pytest.raises(SystemExit):
            await wapiti_main()
            mock_update.assert_called_once_with(None)


@pytest.mark.asyncio
async def test_update_with_proxy():
    """Let's ensure that the proxy is used when updating modules resources."""
    testargs = ["wapiti", "--update", "--proxy", "http://127.0.0.42:1234", "-m", "nikto"]

    with mock.patch.object(sys, 'argv', testargs):
        with mock.patch("wapitiCore.attack.mod_nikto.ModuleNikto") as mock_nikto:
            with pytest.raises(SystemExit):
                await wapiti_main()

            # Check that Nikto is initialized with a Crawler that is configured with a proxy
            async_crawler = mock_nikto.call_args[0][0]
            httpx_client = async_crawler._client
            for httpx_transport in httpx_client._mounts.values():
                proxy_url = httpx_transport._pool._proxy_url
                assert proxy_url == URL(scheme="http", host="127.0.0.42", port=1234, target="/")


@pytest.mark.asyncio
@mock.patch("wapitiCore.main.wapiti.Wapiti.browse")
@mock.patch("wapitiCore.main.wapiti.check_http_auth", return_value=True)
async def test_use_http_creds(mock_check_http_auth, _ ):
    """Let's ensure that the proxy is used when updating modules resources."""
    testargs = ["wapiti", "--auth-user", "test", "--auth-password", "test", "--url", "http://testphp.vulnweb.com/", "-m", "", "--scope", "url"]

    with mock.patch.object(sys, "argv", testargs):
        await wapiti_main()
        mock_check_http_auth.assert_called_once()


@pytest.mark.asyncio
@mock.patch("wapitiCore.main.wapiti.Wapiti.browse")
@mock.patch("wapitiCore.main.wapiti.async_try_form_login", return_value=(False, {}, []))
async def test_use_web_creds(mock_async_try_form_login, _):
    """Let's ensure that the proxy is used when updating modules resources."""
    testargs = [
        "wapiti",
        "--form-user", "test",
        "--form-password", "test",
        "--form-url", "http://testphp.vulnweb.com/login.php",
        "--url", "http://testphp.vulnweb.com/",
        "-m", "",
        "--scope", "url"
    ]

    with mock.patch.object(sys, "argv", testargs):
        await wapiti_main()
        mock_async_try_form_login.assert_called_once()

# Test swagger option with a valid url
@respx.mock
@pytest.mark.asyncio
@mock.patch("wapitiCore.main.wapiti.Wapiti.browse", name="mock_browse")
@mock.patch("wapitiCore.attack.active_scanner.ActiveScanner.attack", name="mock_attack")
async def test_swagger_valid_url(mock_attack, mock_browse):
    swagger_url = "https://petstore.swagger.io/v2/swagger.json"

    swagger_path = Path(__file__).parent.parent / "parsers" / "data" / "swagger.json"
    with swagger_path.open(encoding="utf-8") as file_obj:
        respx.get(swagger_url).mock(
            return_value=httpx.Response(
                200,
                text=file_obj.read()
            )
        )

    testargs = [
        "wapiti",
        "-u", "https://petstore.swagger.io",
        "--swagger", swagger_url,
        "-m", ""
    ]

    with mock.patch.object(sys, "argv", testargs):
        await wapiti_main()
        mock_browse.assert_called_once()
        mock_attack.assert_called_once()

# Test swagger option with an invalid url or when option break
@respx.mock
@pytest.mark.asyncio
async def test_swagger_invalid_url():
    swagger_url = "http://testphp.vulnweb.com/swagger.json"
    respx.get(swagger_url).mock(
        return_value=httpx.Response(
            404,
            text="Not found"
        )
    )

    testargs = [
        "wapiti",
        "-u", "http://testphp.vulnweb.com",
        "--swagger", swagger_url,
        "-m", ""
    ]

    with mock.patch.object(sys, "argv", testargs):
        with pytest.raises(InvalidOptionValue):
            await wapiti_main()


@pytest.mark.asyncio
@mock.patch("wapitiCore.main.wapiti.Wapiti.browse")
@mock.patch("wapitiCore.attack.active_scanner.ActiveScanner.attack")
@mock.patch("wapitiCore.controller.wapiti.Wapiti.add_start_url")
async def test_out_of_scope_swagger(mock_add_start_url, _, __):
    """Test with out-of-scope swagger"""
    test_file = Path(__file__).parent.parent / "parsers" / "data" / "openapi3.yaml"
    testsagrs = [
        "wapiti",
        "--url", "http://testphp.vulnweb.com/",
        "--swagger", str(test_file),
        "-m", ""
    ]

    with mock.patch.object(sys, "argv", testsagrs):
        await wapiti_main()
        mock_add_start_url.assert_not_called()


@pytest.mark.asyncio
@mock.patch("wapitiCore.main.wapiti.Wapiti.browse")
@mock.patch("wapitiCore.attack.active_scanner.ActiveScanner.attack")
@mock.patch("wapitiCore.main.wapiti.validate_cms_choices",return_value=(False, {}, []))
async def test_validate_cms_choices(mock_validate_cms_choices, _, __):
    """Let's ensure that the cms validator is called when the --cms is used."""
    testargs = [
        "wapiti",
        "--url", "http://testphp.vulnweb.com/",
        "-m", "cms",
        "--cms", "drupal,joomla,prestashop,spip,wp",
        "--scope", "url"
    ]

    with mock.patch.object(sys, "argv", testargs):
        await wapiti_main()
        mock_validate_cms_choices.assert_called_once()


@pytest.mark.asyncio
@mock.patch("wapitiCore.main.wapiti.Wapiti.browse")
@mock.patch("wapitiCore.attack.active_scanner.ActiveScanner.attack")
@mock.patch("wapitiCore.main.wapiti.is_mod_cms_set",return_value=(False, {}, []))
async def test_is_mod_cms_set(mock_is_mod_cms_set, _, __):
    """Let's ensure that the --cms option is only used when the module cms is called."""
    testargs = [
        "wapiti",
        "--url", "http://testphp.vulnweb.com/",
        "-m", "cms",
        "--cms", "drupal"
    ]

    with mock.patch.object(sys, "argv", testargs):
        await wapiti_main()
        mock_is_mod_cms_set.assert_called_once()


@pytest.mark.asyncio
@mock.patch("wapitiCore.main.wapiti.Wapiti.browse")
@mock.patch("wapitiCore.attack.active_scanner.ActiveScanner.attack")
@mock.patch("wapitiCore.main.wapiti.is_mod_wapp_or_update_set",return_value=(False, {}, []))
async def test_mod_wapp_is_set(mock_is_mod_wapp_or_update_set, _, __):
    """Let's ensure that the --wapp-url option is only used when the module wapp or update option is called."""
    testargs = [
        "wapiti",
        "--url", "http://testphp.vulnweb.com/",
        "-m", "wapp",
        "--wapp-url", "https://raw.githubusercontent.com/wapiti-scanner/wappalyzerfork/main/"
    ]

    with mock.patch.object(sys, "argv", testargs):
        await wapiti_main()
        mock_is_mod_wapp_or_update_set.assert_called_once()


@pytest.mark.asyncio
@mock.patch("wapitiCore.main.wapiti.Wapiti.browse")
@mock.patch("wapitiCore.attack.active_scanner.ActiveScanner.attack")
@mock.patch("wapitiCore.main.wapiti.is_mod_wapp_or_update_set",return_value=(False, {}, []))
async def test_mod_wapp_is_not_set(mock_is_mod_wapp_or_update_set, _, __):
    """Let's ensure that the --wapp-url option is only used when the module wapp or update option is called."""
    testargs = [
        "wapiti",
        "--url", "http://testphp.vulnweb.com/",
        "-m", "xss",
        "--wapp-url", "https://raw.githubusercontent.com/wapiti-scanner/wappalyzerfork/main/"
    ]

    with mock.patch.object(sys, "argv", testargs):
        await wapiti_main()
        mock_is_mod_wapp_or_update_set.assert_called_once()

@pytest.mark.asyncio
@mock.patch("wapitiCore.main.wapiti.Wapiti.browse")
@mock.patch("wapitiCore.attack.active_scanner.ActiveScanner.attack")
@mock.patch("wapitiCore.main.wapiti.is_mod_wapp_or_update_set",return_value=(False, {}, []))
async def test_mod_wapp_is_set_with_wapp_dir(mock_is_mod_wapp_or_update_set, _, __):
    """Let's ensure that the --wapp-dir option is only used when the module wapp or update option is called."""
    testargs = [
        "wapiti",
        "--url", "http://testphp.vulnweb.com/",
        "-m", "wapp",
        "--wapp-dir", "/"
    ]

    with mock.patch.object(sys, "argv", testargs):
        await wapiti_main()
        mock_is_mod_wapp_or_update_set.assert_called_once()


@pytest.mark.asyncio
@mock.patch("wapitiCore.main.wapiti.Wapiti.browse")
@mock.patch("wapitiCore.attack.active_scanner.ActiveScanner.attack")
@mock.patch("wapitiCore.main.wapiti.is_mod_wapp_or_update_set",return_value=(False, {}, []))
async def test_mod_wapp_is_not_set_with_wapp_dir(mock_is_mod_wapp_or_update_set, _, __):
    """Let's ensure that the --wapp-dir option is only used when the module wapp or update option is called."""
    testargs = [
        "wapiti",
        "--url", "http://testphp.vulnweb.com/",
        "-m", "xss",
        "--wapp-dir", "/"
    ]

    with mock.patch.object(sys, "argv", testargs):
        await wapiti_main()
        mock_is_mod_wapp_or_update_set.assert_called_once()


@pytest.mark.asyncio
@mock.patch("wapitiCore.main.wapiti.Wapiti.browse")
@mock.patch("wapitiCore.attack.active_scanner.ActiveScanner.attack")
@mock.patch("wapitiCore.main.wapiti.is_valid_url", return_value=(False, {}, []))
async def test_is_valid_url(mock_is_valid_url, _, __):
    """Let's ensure that the --wapp-url option is only used when the module wapp or update option is called."""
    testargs = [
        "wapiti",
        "--url", "http://testphp.vulnweb.com/",
        "-m", "wapp",
        "--wapp-url", "https://raw.githubusercontent.com/wapiti-scanner/wappalyzerfork/main/"
    ]

    with mock.patch.object(sys, "argv", testargs):
        await wapiti_main()
        mock_is_valid_url.assert_called_once()


@pytest.mark.asyncio
@mock.patch("wapitiCore.main.wapiti.Wapiti.browse")
@mock.patch("wapitiCore.attack.active_scanner.ActiveScanner.attack")
@mock.patch("wapitiCore.main.wapiti.is_valid_url", return_value=(False, {}, []))
async def test_is_not_valid_url(mock_is_valid_url, _, __):
    """Let's ensure that the --wapp-url option is only used when the module wapp or update option is called."""
    testargs = [
        "wapiti",
        "--url", "http://testphp.vulnweb.com/",
        "-m", "wapp",
        "--wapp-url", "http::raw.githubusercontent.com/wapiti-scanner/wappalyzerfork/main/"
    ]

    with mock.patch.object(sys, "argv", testargs):
        await wapiti_main()
        mock_is_valid_url.assert_called_once()


@pytest.mark.asyncio
@mock.patch("wapitiCore.main.wapiti.Wapiti.browse")
@mock.patch("wapitiCore.attack.active_scanner.ActiveScanner.attack")
async def test_basic_usage(_, __):
    """Test without option"""
    testsagrs = [
        "wapiti",
        "--url", "http://testphp.vulnweb.com/"
    ]

    with mock.patch.object(sys, "argv", testsagrs):
        await wapiti_main()
