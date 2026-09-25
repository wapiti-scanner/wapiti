import asyncio
import types
from pathlib import Path
from typing import Tuple
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx

from wapitiCore.attack.active_scanner import (
    ActiveScanner,
    PassiveTeeCrawler,
    UserChoice,
    activate_method_module,
    module_to_class_name,
)
from wapitiCore.attack.attack import Attack, AttackProtocol
from wapitiCore.attack.passive_scanner import PassiveScanner
from wapitiCore.controller.wapiti import Wapiti
from wapitiCore.net import Request, Response
from wapitiCore.net.classes import CrawlerConfiguration
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.net.sql_persister import SqlPersister

# pylint: disable=protected-access,redefined-outer-name


class MockAttack(AttackProtocol):
    def __init__(self, name, priority=0):
        self.do_get = True
        self.do_post = True
        self.name = name
        self.PRIORITY = priority

    def __repr__(self):
        return f"<MockAttack {self.name}, GET={self.do_get}, POST={self.do_post}>"


@pytest.mark.parametrize(
    "method, expected_get, expected_post",
    [
        ("", False, False),
        ("get", False, True),
        ("post", True, False),
    ],
)
def test_activate_method_module(method, expected_get, expected_post):
    module = MockAttack("whatever", 0)
    activate_method_module(module, method, False)
    assert module.do_get == expected_get
    assert module.do_post == expected_post


@pytest.mark.parametrize(
    "input_str, expected_output",
    [
        ("mod_sql_injection", "ModuleSqlInjection"),
        ("SQL_injection", "ModuleSqlInjection"),
    ],
)
def test_module_to_class_name(input_str, expected_output):
    assert module_to_class_name(input_str) == expected_output


@pytest.mark.parametrize(
    "user_input,expected_choice,should_cancel",
    [
        ("r", UserChoice.REPORT, True),
        ("n", UserChoice.NEXT, True),
        ("q", UserChoice.QUIT, True),
        ("c", UserChoice.CONTINUE, False),
    ],
)
def test_handle_user_interruption(user_input, expected_choice, should_cancel):
    scanner = ActiveScanner(MagicMock(), MagicMock())
    scanner._current_attack_task = MagicMock()
    scanner._current_attack_task.cancel = MagicMock()

    with patch("builtins.input", return_value=user_input):
        scanner.handle_user_interruption(None, None)

    assert scanner._user_choice == expected_choice
    if should_cancel:
        scanner._current_attack_task.cancel.assert_called_once()
    else:
        scanner._current_attack_task.cancel.assert_not_called()


def test_handle_user_interruption_invalid_then_valid():
    scanner = ActiveScanner(MagicMock(), MagicMock())
    scanner._current_attack_task = MagicMock()
    scanner._current_attack_task.cancel = MagicMock()

    with patch("builtins.input", side_effect=["invalid", "q"]):
        scanner.handle_user_interruption(None, None)

    assert scanner._user_choice == UserChoice.QUIT
    scanner._current_attack_task.cancel.assert_called_once()


@pytest.mark.asyncio
@respx.mock
async def test_send_bug_report_success():
    persister = MagicMock()
    crawler_configuration = CrawlerConfiguration(Request("http://example.com/"))
    scanner = ActiveScanner(persister, crawler_configuration)

    fake_request = Request("http://example.com")
    fake_exception = RuntimeError("Boom")

    # Mock the upload endpoint
    respx.post("https://wapiti3.ovh/upload.php").mock(
        return_value=httpx.Response(200, content=b"UPLOAD_OK")
    )

    await scanner.send_bug_report(
        fake_exception, fake_exception.__traceback__, "mod_test", fake_request
    )

    # Make sure the request was successfull
    assert respx.calls.call_count == 1
    call = respx.calls.last
    assert call.request.url == "https://wapiti3.ovh/upload.php"


@pytest.mark.asyncio
@respx.mock
async def test_send_bug_report_request_error():
    persister = MagicMock()
    crawler_configuration = CrawlerConfiguration(Request("http://example.com/"))
    scanner = ActiveScanner(persister, crawler_configuration)

    fake_request = Request("http://example.com")
    fake_exception = RuntimeError("Boom")

    # Fake network error
    respx.post("https://wapiti3.ovh/upload.php").mock(
        side_effect=httpx.RequestError("fail")
    )

    await scanner.send_bug_report(
        fake_exception, fake_exception.__traceback__, "mod_test", fake_request
    )

    # Make sure an attempt to send report was made
    assert respx.calls.call_count == 1


@patch("pathlib.Path.glob", return_value=[Path("mod_broken.py")])
@patch("wapitiCore.attack.active_scanner.import_module")
@patch("wapitiCore.main.log.logging.error")
@patch("wapitiCore.main.log.logging.exception")
def test_load_attack_modules_broken_module(
    mock_log_exc, mock_log_err, mock_import_module, _
):
    """Test that a module raising an unexpected error during class lookup is skipped."""

    # Fake module minimal
    fake_module = types.SimpleNamespace()

    # Simulate broken module
    def broken_getattr(name):
        raise RuntimeError("Simulated broken module")

    fake_module.__getattr__ = broken_getattr

    mock_import_module.return_value = fake_module

    scanner = ActiveScanner(persister=MagicMock(), crawler_configuration=MagicMock())

    # At the end, 0 modules
    assert len(scanner._modules) == 0

    # Make sure error log was called
    mock_log_err.assert_not_called()
    mock_log_exc.assert_called_with(
        "[!] Module %s seems broken and will be skipped", "mod_broken"
    )


@pytest.mark.asyncio
@patch("wapitiCore.attack.active_scanner.import_module")
@patch("wapitiCore.main.log.logging.error")
async def test_update_raises_error_from_module(mock_log_error, mock_import_module):
    """Ensure errors inside module.update bubble up."""
    fake_module = types.SimpleNamespace()
    fake_module.ModuleFoo = lambda *args, **kwargs: types.SimpleNamespace(
        name="foo", update=AsyncMock(side_effect=ValueError("boom"))
    )
    mock_import_module.return_value = fake_module

    persister = MagicMock()
    scanner = ActiveScanner(
        persister, CrawlerConfiguration(Request("http://example.com/"))
    )

    await scanner.update("foo")
    mock_log_error.assert_called_with("[!] Module %s seems broken and will be skipped", "foo", exc_info=True)


@pytest.mark.asyncio
@patch("wapitiCore.attack.active_scanner.import_module")
async def test_update_success(mock_import_module):
    """Ensure update() calls module.update when available."""
    fake_update = AsyncMock()
    fake_module = types.SimpleNamespace()
    fake_module.ModuleFoo = lambda *a, **k: types.SimpleNamespace(
        name="foo", update=fake_update
    )
    mock_import_module.return_value = fake_module

    scanner = ActiveScanner(
        MagicMock(), CrawlerConfiguration(Request("http://example.com/"))
    )
    await scanner.update("foo")

    fake_update.assert_awaited()


@pytest.mark.asyncio
@patch(
    "wapitiCore.attack.active_scanner.import_module", side_effect=ImportError("nope")
)
async def test_update_module_missing(
    _,
):
    """Ensure ImportError in update() is ignored gracefully."""
    scanner = ActiveScanner(
        MagicMock(), CrawlerConfiguration(Request("http://example.com/"))
    )

    # Should not raise, just skip silently
    await scanner.update("foo")


@pytest.fixture
def mock_persister():
    return MagicMock()


async def mock_async_generator(items):
    for item in items:
        yield item


def create_mock_request_response(
    id_prefix: str, count: int
) -> Tuple[Request, Response]:
    request = MagicMock(spec=Request)
    request.path_id = f"{id_prefix}_{count}"
    response = MagicMock(spec=Response)
    return request, response


def create_mock_data(prefix: str, count: int):
    return [create_mock_request_response(prefix, i) for i in range(count)]


@pytest.mark.asyncio
async def test_load_resources_for_module(mock_persister):
    """Test that the correct resources are loaded based on module flags."""
    scanner = ActiveScanner(
        mock_persister, CrawlerConfiguration(Request("http://example.com/"))
    )

    # Test case 1: do_get is True, do_post is False
    get_resources = create_mock_data("get", 3)
    mock_persister.get_links.return_value = mock_async_generator(get_resources)
    mock_persister.get_forms.return_value = mock_async_generator([])

    mock_module = MagicMock(spec=Attack, name="mock_module")
    mock_module.do_get = True
    mock_module.do_post = False
    mock_module.name = "mock_module"

    loaded_resources = [
        res async for res in scanner.load_resources_for_module(mock_module)
    ]

    assert loaded_resources == get_resources
    mock_persister.get_links.assert_called_once_with(attack_module="mock_module")
    mock_persister.get_forms.assert_not_called()

    # Reset mocks for the next test case
    mock_persister.reset_mock()

    # Test case 2: do_get is False, do_post is True
    post_resources = create_mock_data("post", 2)
    mock_persister.get_links.return_value = mock_async_generator([])
    mock_persister.get_forms.return_value = mock_async_generator(post_resources)

    mock_module.do_get = False
    mock_module.do_post = True

    loaded_resources = [
        res async for res in scanner.load_resources_for_module(mock_module)
    ]

    assert loaded_resources == post_resources
    mock_persister.get_links.assert_not_called()
    mock_persister.get_forms.assert_called_once_with(attack_module="mock_module")

    # Reset mocks for the next test case
    mock_persister.reset_mock()

    # Test case 3: Both do_get and do_post are True
    mock_persister.get_links.return_value = mock_async_generator(get_resources)
    mock_persister.get_forms.return_value = mock_async_generator(post_resources)

    mock_module.do_get = True
    mock_module.do_post = True

    loaded_resources = [
        res async for res in scanner.load_resources_for_module(mock_module)
    ]

    expected_resources = get_resources + post_resources
    assert loaded_resources == expected_resources
    mock_persister.get_links.assert_called_once_with(attack_module="mock_module")
    mock_persister.get_forms.assert_called_once_with(attack_module="mock_module")

    # Reset mocks for the next test case
    mock_persister.reset_mock()

    # Test case 4: Both do_get and do_post are False
    mock_persister.get_links.return_value = mock_async_generator([])
    mock_persister.get_forms.return_value = mock_async_generator([])

    mock_module.do_get = False
    mock_module.do_post = False

    loaded_resources = [
        res async for res in scanner.load_resources_for_module(mock_module)
    ]

    assert loaded_resources == []
    mock_persister.get_links.assert_not_called()
    mock_persister.get_forms.assert_not_called()


@pytest.mark.asyncio
async def test_init_attack_modules_adds_enabled_module():
    # Fake module class with proper interface
    class FakeAttack:
        name = "foo"
        PRIORITY = 10

        def __init__(self, crawler, persister, attack_options, crawler_configuration):  # pylint: disable=unused-argument
            self.crawler = crawler
            self.persister = persister

    persister = MagicMock()
    config = CrawlerConfiguration(Request("http://example.com"))
    scanner = ActiveScanner(persister, config)
    crawler = AsyncMock(spec=AsyncCrawler)

    scanner._modules = {"mod_foo": FakeAttack}
    scanner._activated_modules = {"foo": ["GET", "POST"]}

    modules = await scanner.init_attack_modules(crawler)

    assert len(modules) == 1
    assert isinstance(modules[0], FakeAttack)
    # The activate_method_module has attached attributes
    assert modules[0].do_get is True
    assert modules[0].do_post is True


@pytest.mark.asyncio
async def test_init_attack_modules_skips_disabled_module():
    class FakeAttack:
        name = "bar"
        PRIORITY = 5

        def __init__(self, *args, **kwargs):
            pass

    persister = MagicMock()
    config = CrawlerConfiguration(Request("http://example.com"))
    scanner = ActiveScanner(persister, config)
    crawler = AsyncMock(spec=AsyncCrawler)

    scanner._modules = {"mod_bar": FakeAttack}
    scanner._activated_modules = {}  # not enabled

    modules = await scanner.init_attack_modules(crawler)

    assert modules == []


@pytest.mark.asyncio
@patch("wapitiCore.main.log.logging.error")
@patch("wapitiCore.main.log.logging.exception")
async def test_init_attack_modules_handles_broken_module(mock_log_exc, mock_log_err):
    class BrokenAttack:
        name = "broken"
        PRIORITY = 1

        def __init__(self, *args, **kwargs):
            raise RuntimeError("Boom")

    persister = MagicMock()
    config = CrawlerConfiguration(Request("http://example.com"))
    scanner = ActiveScanner(persister, config)
    crawler = AsyncMock(spec=AsyncCrawler)

    scanner._modules = {"mod_broken": BrokenAttack}
    scanner._activated_modules = {"broken": ["GET"]}

    modules = await scanner.init_attack_modules(crawler)

    assert modules == []
    mock_log_err.assert_not_called()
    mock_log_exc.assert_called_with(
        "[!] Module %s seems broken and will be skipped", "mod_broken"
    )


@pytest.mark.asyncio
async def test_init_attack_modules_sorts_by_priority():
    # Define two fake modules with different PRIORITY values
    class LowPriorityAttack:
        name = "low"
        PRIORITY = 50

        def __init__(self, crawler, persister, attack_options, crawler_configuration):
            pass

    class HighPriorityAttack:
        name = "high"
        PRIORITY = 10

        def __init__(self, crawler, persister, attack_options, crawler_configuration):
            pass

    persister = MagicMock()
    config = CrawlerConfiguration(Request("http://example.com"))
    scanner = ActiveScanner(persister, config)
    crawler = AsyncMock(spec=AsyncCrawler)

    # Register both modules
    scanner._modules = {
        "mod_low": LowPriorityAttack,
        "mod_high": HighPriorityAttack,
    }
    scanner._activated_modules = {"low": ["GET"], "high": ["GET"]}

    modules = await scanner.init_attack_modules(crawler)

    # Ensure both modules are returned
    assert {m.name for m in modules} == {"low", "high"}
    # Ensure they are sorted by PRIORITY (high first, then low)
    assert [m.name for m in modules] == ["high", "low"]


@pytest.mark.asyncio
async def test_attack_wrapper_returns_early_when_task_cancelled():
    # A DB error raised while the current attack task is being cancelled (Ctrl+C)
    # must not be treated as a bug: no crash report should be sent.
    scanner = ActiveScanner(MagicMock(), MagicMock())
    task = asyncio.create_task(asyncio.sleep(3600))
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    scanner._current_attack_task = task
    assert task.cancelled()

    scanner._bug_report = True
    scanner.send_bug_report = AsyncMock()

    attack_module = MagicMock()
    attack_module.name = "test_module"
    attack_module.must_attack = AsyncMock(side_effect=Exception("db error during cancellation"))
    attack_module.attack = AsyncMock()

    request = MagicMock()
    response = MagicMock()
    attacked_ids = set()
    semaphore = asyncio.Semaphore(10)

    await scanner._attack_wrapper(attack_module, request, response, attacked_ids, semaphore)

    scanner.send_bug_report.assert_not_called()


def make_fake_attack_class(name: str, passive_scan_responses: bool):
    class FakeAttack:
        PRIORITY = 5

        def __init__(self, crawler, persister, attack_options, crawler_configuration):  # pylint: disable=unused-argument
            self.crawler = crawler

    FakeAttack.name = name
    FakeAttack.passive_scan_responses = passive_scan_responses
    return FakeAttack


@pytest.mark.asyncio
async def test_init_attack_modules_wraps_crawler_according_to_passive_scan_responses():
    config = CrawlerConfiguration(Request("http://example.com"))
    passive_scanner = MagicMock()
    scanner = ActiveScanner(MagicMock(), config, passive_scanner=passive_scanner)
    crawler = AsyncMock(spec=AsyncCrawler)

    scanner._modules = {
        "mod_injection": make_fake_attack_class("injection", passive_scan_responses=True),
        "mod_discovery": make_fake_attack_class("discovery", passive_scan_responses=False),
    }
    scanner._activated_modules = {"injection": ["GET"], "discovery": ["GET"]}

    modules = {module.name: module for module in await scanner.init_attack_modules(crawler)}

    assert isinstance(modules["injection"].crawler, PassiveTeeCrawler)
    assert modules["injection"].crawler._crawler is crawler
    assert modules["injection"].crawler._passive_scanner is passive_scanner
    # Opted-out modules get the raw crawler: no overhead at all
    assert modules["discovery"].crawler is crawler


@pytest.mark.asyncio
async def test_init_attack_modules_uses_raw_crawler_without_passive_scanner():
    config = CrawlerConfiguration(Request("http://example.com"))
    scanner = ActiveScanner(MagicMock(), config)
    crawler = AsyncMock(spec=AsyncCrawler)

    scanner._modules = {"mod_injection": make_fake_attack_class("injection", passive_scan_responses=True)}
    scanner._activated_modules = {"injection": ["GET"]}

    modules = await scanner.init_attack_modules(crawler)

    assert modules[0].crawler is crawler


@pytest.mark.parametrize(
    "module_name, expected",
    [
        ("mod_sql", True),
        ("mod_exec", True),
        ("mod_xss", True),
        ("mod_buster", False),
        ("mod_nikto", False),
        ("mod_wapp", False),
        ("mod_redirect", False),
    ],
)
def test_passive_scan_responses_defaults(module_name, expected):
    """Injection modules keep the default (True), discovery / fingerprint modules opt out."""
    module_classes = ActiveScanner._load_attack_modules()
    assert module_classes[module_name].passive_scan_responses is expected


@pytest.mark.asyncio
async def test_passive_tee_crawler_scans_response_and_returns_it():
    crawler = AsyncMock(spec=AsyncCrawler)
    response = MagicMock(spec=Response)
    crawler.async_send.return_value = response
    passive_scanner = MagicMock()
    passive_scanner.scan_attack_response = AsyncMock()
    request = Request("http://example.com/?id=%27")

    tee = PassiveTeeCrawler(crawler, passive_scanner)
    result = await tee.async_send(request, follow_redirects=True, timeout=3)

    assert result is response
    crawler.async_send.assert_awaited_once_with(request, follow_redirects=True, timeout=3)
    passive_scanner.scan_attack_response.assert_awaited_once_with(request, response)


@pytest.mark.asyncio
@patch("wapitiCore.attack.active_scanner.logging.exception")
async def test_passive_tee_crawler_never_breaks_the_attack(mock_log_exc):
    crawler = AsyncMock(spec=AsyncCrawler)
    response = MagicMock(spec=Response)
    crawler.async_send.return_value = response
    passive_scanner = MagicMock()
    passive_scanner.scan_attack_response = AsyncMock(side_effect=ValueError("broken passive module"))

    tee = PassiveTeeCrawler(crawler, passive_scanner)
    result = await tee.async_send(Request("http://example.com/"))

    assert result is response
    mock_log_exc.assert_called_once()


@pytest.mark.asyncio
async def test_passive_tee_crawler_propagates_request_errors_without_scanning():
    crawler = AsyncMock(spec=AsyncCrawler)
    crawler.async_send.side_effect = httpx.ReadTimeout("timeout")
    passive_scanner = MagicMock()
    passive_scanner.scan_attack_response = AsyncMock()

    tee = PassiveTeeCrawler(crawler, passive_scanner)
    with pytest.raises(httpx.ReadTimeout):
        await tee.async_send(Request("http://example.com/"))

    passive_scanner.scan_attack_response.assert_not_awaited()


@pytest.mark.asyncio
async def test_passive_tee_crawler_does_not_consume_streamed_responses():
    crawler = AsyncMock(spec=AsyncCrawler)
    passive_scanner = MagicMock()
    passive_scanner.scan_attack_response = AsyncMock()

    tee = PassiveTeeCrawler(crawler, passive_scanner)
    await tee.async_send(Request("http://example.com/"), stream=True)

    passive_scanner.scan_attack_response.assert_not_awaited()


def test_passive_tee_crawler_forwards_other_attributes():
    crawler = MagicMock()
    crawler.timeout = 7

    tee = PassiveTeeCrawler(crawler, MagicMock())

    assert tee.timeout == 7


@pytest.mark.asyncio
@pytest.mark.parametrize("user_choice", [UserChoice.CONTINUE, UserChoice.QUIT])
@patch("wapitiCore.attack.active_scanner.AsyncCrawler.with_configuration")
async def test_attack_restores_passive_state_before_and_persists_it_after_the_modules(
    mock_with_configuration, user_choice
):
    mock_with_configuration.return_value.__aenter__.return_value = AsyncMock(spec=AsyncCrawler)
    calls = []
    passive_scanner = MagicMock()
    passive_scanner.restore_state = AsyncMock(side_effect=lambda: calls.append("restore"))
    passive_scanner.persist_state = AsyncMock(side_effect=lambda: calls.append("persist"))
    persister = MagicMock()
    persister.close = AsyncMock()
    scanner = ActiveScanner(persister, MagicMock(), passive_scanner=passive_scanner)

    attack_module = MagicMock()
    attack_module.do_get, attack_module.do_post, attack_module.require = True, False, []
    scanner.init_attack_modules = AsyncMock(return_value=[attack_module])

    async def run_attack_module(_):
        calls.append("attack")
        scanner._user_choice = user_choice  # e.g. the user pressed Ctrl+C then "q"

    scanner.run_attack_module = run_attack_module

    assert await scanner.attack() is (user_choice != UserChoice.QUIT)
    # Even when quitting, the state is saved so that a later resumed attack keeps deduplicating
    assert calls == ["restore", "attack", "persist"]


YSOD_BODY = (
    "<html><head><title>Server Error in '/' Application.</title></head><body>"
    "<b>Exception Details: </b>System.Data.SqlClient.SqlException: Unclosed quotation mark.<br>"
    "<pre>[SqlException (0x80131904): Unclosed quotation mark.]\n</pre></body></html>"
)


class ModuleFakeInjection(Attack):
    """Sends a single quote in the id parameter, like an injection module would."""
    name = "fake_injection"

    async def attack(self, request: Request, response: Response):
        await self.crawler.async_send(Request("http://perdu.com/", get_params=[["id", "'"]]))


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize("passive_scan_responses", [True, False], ids=["opted in", "opted out"])
async def test_stacktrace_triggered_by_a_payload_is_reported_on_the_evil_request(
    tmp_path, passive_scan_responses
):
    respx.get("http://perdu.com/", params={"id": "'"}).mock(
        return_value=httpx.Response(500, text=YSOD_BODY, headers={"content-type": "text/html"})
    )
    persister = SqlPersister(str(tmp_path / "scan.db"))
    await persister.create()
    await persister.set_root_url("http://perdu.com/")

    passive_scanner = PassiveScanner(persister=persister)
    passive_scanner.set_modules({"stacktrace_disclosure": [], "http_headers": []})
    config = CrawlerConfiguration(Request("http://perdu.com/"))
    scanner = ActiveScanner(persister, config, passive_scanner=passive_scanner)
    scanner._modules = {"mod_fake_injection": ModuleFakeInjection}
    scanner._activated_modules = {"fake_injection": ["GET"]}

    with patch.object(ModuleFakeInjection, "passive_scan_responses", passive_scan_responses):
        async with AsyncCrawler.with_configuration(config) as crawler:
            modules = await scanner.init_attack_modules(crawler)
            await modules[0].attack(Request("http://perdu.com/"), MagicMock(spec=Response))

    payloads = [payload async for payload in persister.get_payloads()]
    await persister.close()

    if not passive_scan_responses:
        assert not payloads
        return

    # Header based passive modules do not run on attack traffic
    assert [payload.module for payload in payloads] == ["stacktrace_disclosure"]
    assert payloads[0].evil_request.get_params == [["id", "'"]]
    assert payloads[0].response.status == 500


def test_controller_shares_its_passive_scanner_with_the_active_scanner(tmp_path):
    wapiti = Wapiti(Request("http://perdu.com/"), session_dir=str(tmp_path))
    assert wapiti.active_scanner._passive_scanner is wapiti.passive_scaner
