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


DOTNET_404 = (
    "<html><head><title>The resource cannot be found.</title></head><body>\n"
    "<h2>Server Error in '/' Application.</h2>\n"
    "<h3>The resource cannot be found.</h3>\n"
    "Description: HTTP 404. The resource you are looking for has been removed, "
    "had its name changed, or is temporarily unavailable.\n"
    "Requested URL: /missing\n"
    "</body></html>"
)

# Classic ASP.NET (full framework) Yellow Screen of Death, release build with
# no PDB: the frames carry no source path, but the "[SqlException (0x…): …]"
# tag still discloses the SQL error. Observed format.
DOTNET_YSOD_NO_SOURCE = (
    "Server Error in '/' Application.\n"
    "[SqlException (0x80131904): Invalid column name 'foo'.]\n"
    "   System.Data.SqlClient.SqlConnection.OnError(SqlException ex) +5314379\n"
    "   System.Data.SqlClient.SqlInternalConnection.OnError(SqlException ex) +239\n"
)

DOTNET_YSOD_CLASSIC = (
    "[NullReferenceException: Object reference not set to an instance of an object.]\n"
    "   WebApplication1._Default.Page_Load(Object sender, EventArgs e) in "
    "c:\\inetpub\\wwwroot\\Default.aspx.cs:42\n"
)

# ASP.NET Core, release build (no PDB), a custom exception handler echoing
# Exception.ToString(): no frame has a source path, yet the message leaks the
# full SQL query and a connection string with credentials. Reproduced with
# a real .NET 8 app under Linux/Docker.
DOTNET_NO_PDB_SQL_LEAK = (
    "System.InvalidOperationException: Error executing query "
    "[SELECT id, name, secret_password FROM users WHERE name = 'admin'] "
    "against connection Server=db-prod-01;Database=customers;User Id=sa;\n"
    "   at Program.<>c.<<Main>$>b__0_2()\n"
    "   at lambda_method2(Closure, Object, HttpContext)\n"
)


def test_dotnet_404_page_is_not_a_false_positive(module):
    """A plain ASP.NET 404 page (banner only, no exception) must not trigger."""
    request, response = create_mock_objects(DOTNET_404)
    vulns = list(get_all_vulnerabilities(module, request, response))
    assert len(vulns) == 0


def test_dotnet_ysod_without_source_path_is_reported(module):
    """A YSOD exception tag without a source path is still a disclosure."""
    request, response = create_mock_objects(DOTNET_YSOD_NO_SOURCE)
    vulns = list(get_all_vulnerabilities(module, request, response))
    assert len(vulns) == 1
    assert ".NET" in vulns[0].info


def test_dotnet_no_pdb_message_leak_is_reported(module):
    """A pathless release-build trace still leaks SQL/credentials via the message."""
    request, response = create_mock_objects(DOTNET_NO_PDB_SQL_LEAK)
    vulns = list(get_all_vulnerabilities(module, request, response))
    assert len(vulns) == 1
    assert ".NET" in vulns[0].info


def test_dotnet_lowercase_log_key_is_not_a_false_positive(module):
    """A lowercase dotted log key ('app.db.error:') must not be taken for a type."""
    content = "app.db.error: connection refused\napp.cache.warning: stale entry"
    request, response = create_mock_objects(content)
    vulns = list(get_all_vulnerabilities(module, request, response))
    assert len(vulns) == 0


def test_dotnet_classic_ysod_frame_with_path_is_reported(module):
    """The classic YSOD frame form (no 'at'/'line', but a source path) triggers."""
    request, response = create_mock_objects(DOTNET_YSOD_CLASSIC)
    vulns = list(get_all_vulnerabilities(module, request, response))
    assert len(vulns) == 1
    assert ".NET" in vulns[0].info


def test_node_timestamp_line_is_not_a_false_positive(module):
    """An indented 'at HH:MM:SS' log/timestamp line must not look like a V8 frame."""
    content = "job started\n    at 12:30:45\n    at 02:00:00\nfinished"
    request, response = create_mock_objects(content)
    vulns = list(get_all_vulnerabilities(module, request, response))
    assert len(vulns) == 0


def test_java_trace_is_not_misreported_as_dotnet(module):
    """A JVM trace (lowercase package) must yield only a Java finding, not .NET."""
    request, response = create_mock_objects(JAVA_TRACE)
    vulns = list(get_all_vulnerabilities(module, request, response))
    labels = {label for label in ("Java", ".NET") if any(label in v.info for v in vulns)}
    assert labels == {"Java"}


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
