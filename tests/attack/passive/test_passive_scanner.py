import types
from unittest.mock import MagicMock, patch, ANY
from pathlib import Path

import pytest

from wapitiCore.attack.passive_scanner import PassiveScanner
from wapitiCore.net.sql_persister import SqlPersister

# pylint: disable=redefined-outer-name,protected-access


@pytest.fixture
def mock_persister():
    return MagicMock(spec=SqlPersister)


@patch("pathlib.Path.glob", return_value=[Path("mod_broken.py")])
@patch("wapitiCore.main.log.logging.error")
def test_import_error_is_handled(mock_log_error, _, mock_persister):
    """Test that a module raising ImportError is skipped and the error is logged."""
    scanner = PassiveScanner(persister=mock_persister)

    assert len(scanner._modules) == 0
    mock_log_error.assert_called_with(
        "[!] Unable to import module %s: %s", "mod_broken", ANY
    )


@patch("pathlib.Path.glob", return_value=[])
@patch("wapitiCore.attack.passive_scanner.log_blue")
def test_log_summary_reports_only_modules_with_suppressed_findings(mock_log_blue, _, mock_persister):
    """Only modules that actually suppressed alerts are logged."""
    scanner = PassiveScanner(persister=mock_persister)

    noisy = MagicMock()
    noisy.suppressed_findings = 3
    silent = MagicMock()
    silent.suppressed_findings = 0
    scanner._modules = {"noisy": noisy, "silent": silent}

    scanner.log_summary()

    # A header plus exactly one detail line for the only noisy module.
    mock_log_blue.assert_any_call(
        "    {0}: {1} similar alert(s) suppressed", "noisy", 3
    )
    detail_calls = [
        call for call in mock_log_blue.call_args_list
        if call.args and call.args[0].startswith("    {0}")
    ]
    assert len(detail_calls) == 1


@patch("pathlib.Path.glob", return_value=[])
@patch("wapitiCore.attack.passive_scanner.log_blue")
def test_log_summary_stays_silent_when_nothing_suppressed(mock_log_blue, _, mock_persister):
    """No output at all (not even a header) when no alert was suppressed."""
    scanner = PassiveScanner(persister=mock_persister)

    silent = MagicMock()
    silent.suppressed_findings = 0
    scanner._modules = {"silent": silent}

    scanner.log_summary()

    mock_log_blue.assert_not_called()


@patch("pathlib.Path.glob", return_value=[Path("mod_broken.py")])
@patch("wapitiCore.attack.passive_scanner.import_module")
@patch("wapitiCore.main.log.logging.error")
@patch("wapitiCore.main.log.logging.exception")
def test_broken_module_is_skipped(
    mock_log_exc, mock_log_err, mock_import_module, _, mock_persister
):
    """Test that a module raising an unexpected error during instantiation is skipped."""
    fake_module = types.SimpleNamespace()

    def broken_getattr(name):
        raise AttributeError("Simulated broken module")

    fake_module.__getattribute__ = broken_getattr
    mock_import_module.return_value = fake_module

    scanner = PassiveScanner(persister=mock_persister)

    # No modules should be loaded
    assert not scanner._modules

    # Logs should have been called
    mock_log_err.assert_not_called()
    mock_log_exc.assert_called_with(
        "[!] Module %s seems broken and will be skipped", "mod_broken"
    )
