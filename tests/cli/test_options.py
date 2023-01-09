import sys
from asyncio import Event
from unittest import mock

from httpcore import URL
import pytest

from wapitiCore.attack.attack import common_modules, all_modules, passive_modules
from wapitiCore.net import Request
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
@mock.patch("wapitiCore.main.wapiti.Wapiti.update")
async def test_update_with_modules(mock_update):
    testargs = ["wapiti", "--update", "-m", "wapp,nikto"]
    with mock.patch.object(sys, 'argv', testargs):
        with pytest.raises(SystemExit):
            await wapiti_main()
            mock_update.assert_called_once_with("wapp,nikto")


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
    testargs = ["wapiti", "-a", "test%test", "--url", "http://testphp.vulnweb.com/", "-m", "", "--scope", "url"]

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
        "--form-cred", "test%test",
        "--form-url", "http://testphp.vulnweb.com/login.php",
        "--url", "http://testphp.vulnweb.com/",
        "-m", "",
        "--scope", "url"
    ]

    with mock.patch.object(sys, "argv", testargs):
        await wapiti_main()
        mock_async_try_form_login.assert_called_once()
