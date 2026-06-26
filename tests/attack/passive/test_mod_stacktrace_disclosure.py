from unittest.mock import MagicMock
from typing import Generator, Any

import pytest

from wapitiCore.attack.modules.passive.mod_stacktrace_disclosure import (
    ModuleStacktraceDisclosure,
)
from wapitiCore.definitions.stacktrace_disclosure import StacktraceDisclosureFinding
from wapitiCore.language.vulnerability import MEDIUM_LEVEL
from wapitiCore.model.vulnerability import VulnerabilityInstance
from wapitiCore.net import Request, Response

# pylint: disable=redefined-outer-name


def create_mock_objects(content: str, content_type: str = "text/html"):
    """Helper to create mock Request and Response objects."""
    request = MagicMock(spec=Request)
    request.url = "http://test.com/"
    response = MagicMock(spec=Response)
    response.content = content
    response.type = content_type
    return request, response


@pytest.fixture
def module():
    """Fixture to provide a fresh instance of the module."""
    return ModuleStacktraceDisclosure()


def get_all_vulnerabilities(
    module: ModuleStacktraceDisclosure, request: Request, response: Response
) -> Generator[VulnerabilityInstance, Any, None]:
    """Helper to get all vulnerabilities from the generator."""
    yield from module.analyze(request, response)


PYTHON_TRACEBACK = (
    "Traceback (most recent call last):\n"
    '  File "/app/views.py", line 42, in index\n'
    "    return 1 / 0\n"
    "ZeroDivisionError: division by zero\n"
)

PHP_FATAL = (
    "<b>Fatal error</b>: Uncaught Error: Call to undefined function foo() "
    "in /var/www/html/index.php:12\nStack trace:\n#0 {main}\n"
    "  thrown in /var/www/html/index.php on line 12"
)

JAVA_TRACE = (
    "java.lang.NullPointerException\n"
    "\tat com.example.app.Service.process(Service.java:88)\n"
    "\tat com.example.app.Controller.handle(Controller.java:33)\n"
    "Caused by: java.lang.IllegalStateException\n"
)

DOTNET_YSOD = (
    "Server Error in '/' Application.\n"
    "[SqlException (0x80131904): Invalid column name 'foo'.]\n"
    "   at System.Data.SqlClient.SqlConnection.OnError(SqlException ex) in "
    "C:\\src\\SqlConnection.cs:line 1024\n"
)

NODE_TRACE = (
    "Error: connect ECONNREFUSED 127.0.0.1:5432\n"
    "    at TCPConnectWrap.afterConnect (node:net:1494:16)\n"
    "    at Object.<anonymous> (/app/server.js:10:15)\n"
)

RUBY_TRACE = (
    "/app/controllers/users_controller.rb:24:in `show'\n"
    "  from /app/lib/router.rb:8:in `dispatch'\n"
)

GO_PANIC = (
    "panic: runtime error: invalid memory address or nil pointer dereference\n"
    "goroutine 1 [running]:\n"
    "main.handler(0x0, 0x0)\n"
)


@pytest.mark.parametrize(
    "content, expected_label",
    [
        (PYTHON_TRACEBACK, "Python"),
        (PHP_FATAL, "PHP"),
        (JAVA_TRACE, "Java"),
        (DOTNET_YSOD, ".NET"),
        (NODE_TRACE, "Node.js"),
        (RUBY_TRACE, "Ruby"),
        (GO_PANIC, "Go"),
    ],
)
def test_stacktrace_detected(module, content, expected_label):
    """Each language-specific stack trace is detected with MEDIUM severity."""
    request, response = create_mock_objects(content)
    vulns = list(get_all_vulnerabilities(module, request, response))

    assert len(vulns) >= 1
    assert any(expected_label in vuln.info for vuln in vulns)
    assert all(vuln.severity == MEDIUM_LEVEL for vuln in vulns)
    assert all(vuln.finding_class == StacktraceDisclosureFinding for vuln in vulns)


def test_no_stacktrace_in_clean_response(module):
    """No vulnerability is reported on benign content."""
    content = (
        "<html><body><h1>Welcome</h1>"
        "<p>Everything is working as expected.</p></body></html>"
    )
    request, response = create_mock_objects(content)
    vulns = list(get_all_vulnerabilities(module, request, response))
    assert len(vulns) == 0


def test_no_false_positive_on_prose_mentioning_at(module):
    """Plain prose that merely mentions 'at' or '.java' must not trigger."""
    content = (
        "Our team meets at 10:00 to discuss the Main.java refactoring "
        "and review the traceback handling guidelines."
    )
    request, response = create_mock_objects(content)
    vulns = list(get_all_vulnerabilities(module, request, response))
    assert len(vulns) == 0


def test_unsupported_content_type_skipped(module):
    """Binary/unsupported content types are not analyzed."""
    request, response = create_mock_objects(PYTHON_TRACEBACK, content_type="image/png")
    vulns = list(get_all_vulnerabilities(module, request, response))
    assert len(vulns) == 0


def test_empty_content_skipped(module):
    """Empty responses produce no finding."""
    request, response = create_mock_objects("")
    vulns = list(get_all_vulnerabilities(module, request, response))
    assert len(vulns) == 0


def test_detected_in_json_response(module):
    """Stack traces leaked inside a JSON error body are detected."""
    content = (
        '{"error": "Internal Server Error", "trace": '
        '"Traceback (most recent call last):\\n  File ..."}'
    )
    request, response = create_mock_objects(content, content_type="application/json")
    vulns = list(get_all_vulnerabilities(module, request, response))
    assert len(vulns) == 1
    assert "Python" in vulns[0].info


def test_deduplication_same_trace(module):
    """The same trace appearing twice is reported only once."""
    content = PYTHON_TRACEBACK + "\n...\n" + PYTHON_TRACEBACK
    request, response = create_mock_objects(content)
    vulns = list(get_all_vulnerabilities(module, request, response))
    assert len(vulns) == 1


def test_multiple_languages_reported_separately(module):
    """Different language traces in one response yield distinct findings."""
    content = PYTHON_TRACEBACK + "\n" + GO_PANIC
    request, response = create_mock_objects(content)
    vulns = list(get_all_vulnerabilities(module, request, response))
    labels = {label for label in ("Python", "Go") if any(label in v.info for v in vulns)}
    assert labels == {"Python", "Go"}
