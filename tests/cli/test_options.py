import sys
from asyncio import Event
from time import monotonic
from unittest import mock

from httpcore import URL
import httpx
import pytest

from wapitiCore.attack.attack import common_modules, all_modules, passive_modules
from wapitiCore.net import Request, Response
from wapitiCore.main.wapiti import wapiti_main
from wapitiCore.controller.wapiti import Wapiti


@pytest.mark.asyncio
async def test_options():
    class CustomMock:
        CONFIG_DIR = ""

        def __init__(self):
            pass

        async def count_paths(self):
            return 0

    with mock.patch("os.makedirs", return_value=True):
        stop_event = Event()
        cli = Wapiti(Request("http://perdu.com/"), session_dir="/dev/shm")
        cli.persister = CustomMock()
        crawler = mock.MagicMock()
        cli.set_attack_options({"timeout": 10})

        cli.set_modules("-all,xxe")
        attak_modules = await cli._load_attack_modules(stop_event, crawler)
        assert {module.name for module in attak_modules if module.do_get or module.do_post} == {"xxe"}

        cli.set_modules("xxe")
        attak_modules = await cli._load_attack_modules(stop_event, crawler)
        assert {module.name for module in attak_modules if module.do_get or module.do_post} == {"xxe"}

        cli.set_modules("common,xxe")
        attak_modules = await cli._load_attack_modules(stop_event, crawler)
        activated_modules = {module.name for module in attak_modules if module.do_get or module.do_post}
        assert len(activated_modules) == len(common_modules) + 1

        cli.set_modules("common,-exec")
        attak_modules = await cli._load_attack_modules(stop_event, crawler)
        activated_modules = {module.name for module in attak_modules if module.do_get or module.do_post}
        assert len(activated_modules) == len(common_modules) - 1

        cli.set_modules("all,-xxe")
        attak_modules = await cli._load_attack_modules(stop_event, crawler)
        activated_modules = {module.name for module in attak_modules if module.do_get or module.do_post}
        assert len(activated_modules) == len(all_modules) - 1

        cli.set_modules("all,-common")
        attak_modules = await cli._load_attack_modules(stop_event, crawler)
        activated_modules = {module.name for module in attak_modules if module.do_get or module.do_post}
        assert len(activated_modules) == len(all_modules) - len(common_modules)

        cli.set_modules("common,-all,xss")
        attak_modules = await cli._load_attack_modules(stop_event, crawler)
        activated_modules = {module.name for module in attak_modules if module.do_get or module.do_post}
        assert len(activated_modules) == 1

        cli.set_modules("passive")
        attak_modules = await cli._load_attack_modules(stop_event, crawler)
        activated_modules = {module.name for module in attak_modules if module.do_get or module.do_post}
        assert len(activated_modules) == len(passive_modules)

        cli.set_modules("passive,xxe")
        attak_modules = await cli._load_attack_modules(stop_event, crawler)
        activated_modules = {module.name for module in attak_modules if module.do_get or module.do_post}
        assert len(activated_modules) == len(passive_modules) + 1

        cli.set_modules("passive,-wapp")
        attak_modules = await cli._load_attack_modules(stop_event, crawler)
        activated_modules = {module.name for module in attak_modules if module.do_get or module.do_post}
        assert len(activated_modules) == len(passive_modules) - 1

        cli.set_modules("cms")
        attak_modules = await cli._load_attack_modules(stop_event, crawler)
        activated_modules = {module.name for module in attak_modules if module.do_get or module.do_post}
        assert len(activated_modules) == 1

        # Empty module list: no modules will be used
        cli.set_modules("")
        attak_modules = await cli._load_attack_modules(stop_event, crawler)
        activated_modules = {module.name for module in attak_modules if module.do_get or module.do_post}
        assert not activated_modules

        # Use default settings: only use "commons" modules
        cli.set_modules(None)
        attak_modules = await cli._load_attack_modules(stop_event, crawler)
        activated_modules = {module.name for module in attak_modules if module.do_get or module.do_post}
        assert activated_modules == set(common_modules)


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
        stop_event = Event()
        cli = Wapiti(Request("http://perdu.com/"), session_dir="/dev/shm")
        cli.persister = CustomMock()
        cli.set_max_attack_time(max_attack_time)
        cli.set_attack_options({"timeout": 10, "tasks": 1})

        cli.set_modules("all")
        time = monotonic()
        await cli.attack(stop_event)
        max_run_duration = max_attack_time * (len(all_modules) + delta) # execution time for all modules + delta of uncertainty
        assert monotonic() - time < max_run_duration


@pytest.mark.asyncio
@mock.patch("wapitiCore.main.wapiti.Wapiti.update")
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
@mock.patch("wapitiCore.main.wapiti.Wapiti.update")
async def test_update_without_modules(mock_update):
    """Ensure that no module should be updated when no module is requested."""
    testargs = ["wapiti", "--update"]
    with mock.patch.object(sys, 'argv', testargs):
        with pytest.raises(SystemExit):
            await wapiti_main()
            mock_update.assert_called_once_with(None)

@pytest.mark.asyncio
@mock.patch("wapitiCore.main.wapiti.Wapiti.update")
async def test_update_with_wapp_url(mock_update):
    """Ensure that no module should be updated when no module is requested."""
    testargs = ["wapiti", "--update", "-m", "wapp", "--wapp-url", "https://raw.githubusercontent.com/wapiti-scanner/wappalyzerfork/main/"]
    with mock.patch.object(sys, 'argv', testargs):
        with pytest.raises(SystemExit):
            await wapiti_main()
            mock_update.assert_called_once_with(None)

@pytest.mark.asyncio
@mock.patch("wapitiCore.main.wapiti.Wapiti.update")
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
@mock.patch("wapitiCore.main.wapiti.Wapiti.attack")
@mock.patch("wapitiCore.main.wapiti.check_http_auth", return_value=True)
async def test_use_http_creds(mock_check_http_auth, _, __):
    """Let's ensure that the proxy is used when updating modules resources."""
    testargs = ["wapiti", "--auth-user", "test", "--auth-password", "test", "--url", "http://testphp.vulnweb.com/", "-m", "", "--scope", "url"]

    with mock.patch.object(sys, "argv", testargs):
        await wapiti_main()
        mock_check_http_auth.assert_called_once()


@pytest.mark.asyncio
@mock.patch("wapitiCore.main.wapiti.Wapiti.browse")
@mock.patch("wapitiCore.main.wapiti.Wapiti.attack")
@mock.patch("wapitiCore.main.wapiti.async_try_form_login", return_value=(False, {}, []))
async def test_use_web_creds(mock_async_try_form_login, _, __):
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
@pytest.mark.asyncio
@mock.patch("wapitiCore.main.wapiti.Wapiti.browse")
@mock.patch("wapitiCore.main.wapiti.Wapiti.attack")
async def test_swagger_valid_url(mock_browse, _):
    testargs = [
        "wapiti",
        "-u", "https://petstore.swagger.io",
        "--swagger", "https://petstore.swagger.io/v2/swagger.json",
        "-m", ""
    ]

    with mock.patch.object(sys, "argv", testargs):
        await wapiti_main()
        mock_browse.assert_called_once()

# Test swagger option with an invalid url or when option break
@pytest.mark.asyncio
@mock.patch("wapitiCore.main.wapiti.Wapiti.browse")
@mock.patch("wapitiCore.main.wapiti.Wapiti.attack")
async def test_swagger_invalid_url(mock_browse, _):
    testargs = [
        "wapiti",
        "-u", "http://testphp.vulnweb.com",
        "--swagger", "http://testphp.vulnweb.com/swagger.json",
        "-m", ""
    ]

    with mock.patch.object(sys, "argv", testargs):
        # will not raise an exception because of the invalid url
        await wapiti_main()
        mock_browse.assert_called_once()


@pytest.mark.asyncio
@mock.patch("wapitiCore.main.wapiti.Wapiti.browse")
@mock.patch("wapitiCore.main.wapiti.Wapiti.attack")
@mock.patch("wapitiCore.controller.wapiti.Wapiti.add_start_url")
async def test_out_of_scope_swagger(mock_add_start_url, _, __):
    """Test with out of scope swagger"""
    testsagrs = [
        "wapiti",
        "--url", "http://testphp.vulnweb.com/",
        "--swagger", "./tests/data/openapi3.yaml",
        "-m", ""
    ]

    with mock.patch.object(sys, "argv", testsagrs):
        await wapiti_main()
        mock_add_start_url.assert_not_called()


@pytest.mark.asyncio
@mock.patch("wapitiCore.main.wapiti.Wapiti.browse")
@mock.patch("wapitiCore.main.wapiti.Wapiti.attack")
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
@mock.patch("wapitiCore.main.wapiti.Wapiti.attack")
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
@mock.patch("wapitiCore.main.wapiti.Wapiti.attack")
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
@mock.patch("wapitiCore.main.wapiti.Wapiti.attack")
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
@mock.patch("wapitiCore.main.wapiti.Wapiti.attack")
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
@mock.patch("wapitiCore.main.wapiti.Wapiti.attack")
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
@mock.patch("wapitiCore.main.wapiti.Wapiti.attack")
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
@mock.patch("wapitiCore.main.wapiti.Wapiti.attack")
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
@mock.patch("wapitiCore.main.wapiti.Wapiti.attack")
async def test_basic_usage(_, __):
    """Test without option"""
    testsagrs = [
        "wapiti",
        "--url", "http://testphp.vulnweb.com/"
    ]

    with mock.patch.object(sys, "argv", testsagrs):
        await wapiti_main()
