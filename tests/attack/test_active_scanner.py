from typing import Dict

import pytest
from unittest.mock import patch, MagicMock

from wapitiCore.attack.active_scanner import (
    activate_method_module, filter_modules_with_options, module_to_class_name, ActiveScanner, UserChoice
)
from wapitiCore.attack.attack import common_modules, AttackProtocol


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
    ]
)
def test_activate_method_module(method, expected_get, expected_post):
    module = MockAttack("whatever", 0)
    activate_method_module(module, method, False)
    assert module.do_get == expected_get
    assert module.do_post == expected_post


@pytest.mark.parametrize(
    "option_string, loaded_modules, expected_names",
    [
        (None, {m: MockAttack(m) for m in common_modules}, common_modules),
        ("", {"xss": MockAttack("xss")}, set()),
        ("xss:get", {"xss": MockAttack("xss")}, {"xss"}),
        ("xss,sql,-sql", {"xss": MockAttack("xss"), "sql": MockAttack("sql")}, {"xss"}),
        ("xss,", {"xss": MockAttack("xss")}, {"xss"}),
    ],
    ids=[
        "no options",
        "no modules",
        "xss:get",
        "xss,sql,-sql",
        "xss,",
    ]
)
def test_filter_modules_with_options(option_string, loaded_modules: Dict[str, MockAttack], expected_names: set):
    result = filter_modules_with_options(option_string, loaded_modules)
    result_names = {mod.name for mod in result}
    assert result_names == expected_names


@pytest.mark.parametrize("input_str, expected_output", [
    ("mod_sql_injection", "ModuleSqlInjection"),
    ("SQL_injection", "ModuleSqlInjection"),
])
def test_module_to_class_name(input_str, expected_output):
    assert module_to_class_name(input_str) == expected_output


@pytest.mark.parametrize(
    "user_input,expected_choice,should_cancel",
    [
        ("r", UserChoice.REPORT, True),
        ("n", UserChoice.NEXT, True),
        ("q", UserChoice.QUIT, True),
        ("c", UserChoice.CONTINUE, False),
    ]
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