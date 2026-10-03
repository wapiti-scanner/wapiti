import re
from typing import Generator, Any
from urllib.parse import urlsplit

from wapitiCore.attack.modules.passive.base import PassiveModule
from wapitiCore.definitions.stacktrace_disclosure import StacktraceDisclosureFinding
from wapitiCore.language.vulnerability import MEDIUM_LEVEL
from wapitiCore.main.log import log_orange

from wapitiCore.model.vulnerability import VulnerabilityInstance
from wapitiCore.net import Request, Response

# Each pattern is anchored on the *structure* of a stack trace (frame layout,
# error banner, …) rather than on an isolated keyword, to keep false positives
# low. Order matters only for the label reported when several would match.
STACKTRACE_PATTERNS = [
    (
        "Python",
        # "Traceback (most recent call last):" is unambiguous on its own.
        re.compile(r"Traceback \(most recent call last\):"),
    ),
    (
        "PHP",
        # Fatal error: ... in /path/file.php on line 42  /  "Stack trace: #0 ..."
        re.compile(
            r"(?:Fatal error|Parse error|Warning|Notice|Deprecated):.{0,200}?"
            r" in .{1,200}?\.php(?:\(\d+\))? on line \d+"
            r"|Stack trace:\s*#0\s",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "Java",
        # A real JVM frame: "\tat com.example.Foo.bar(Foo.java:42)" or "Caused by:".
        re.compile(
            r"^\s*at [\w.$/]+\([\w$ .-]+\.java:\d+\)"
            r"|Caused by: [\w.$]+(?:Exception|Error)"
            r"|Exception in thread \"",
            re.MULTILINE,
        ),
    ),
    (
        ".NET",
        # Three independent signals of a genuine .NET error disclosure:
        # (1) a CLR stack frame leaking a source path (and, as is standard, a
        #     line number): "at Ns.Type.Method(args) in C:\src\File.cs:line 42"
        #     (Exception.ToString()/ASP.NET Core form) or the classic Yellow
        #     Screen of Death form without "at "/"line " ("…File.cs:42");
        # (2) a fully-qualified exception type followed by its message
        #     ("System.Data.SqlClient.SqlException: Invalid column name 'x'").
        #     This is what actually leaks SQL, connection strings and schema,
        #     and it survives release builds where the frames carry no source
        #     path (e.g. Exception.ToString() echoed back by a custom handler);
        # (3) the classic YSOD exception tag with its HRESULT
        #     ("[SqlException (0x80131904): …]").
        # The bare "Server Error in '…' Application" banner is deliberately NOT
        # matched: a plain 404 page carries it with no exception disclosure.
        # Signal (2) requires a namespaced type whose every segment is in
        # PascalCase (upper-case initial), so a lowercase log key like
        # "app.db.error:" and a Java type like "java.lang.RuntimeException:"
        # (lower-case package) do not trigger it — the latter is caught by the
        # dedicated Java pattern instead.
        re.compile(
            r"^\s*(?:at )?[\w.<>+`\[\]]+\(.*?\) in .+?:(?:line )?\d+"
            r"|\b[A-Z]\w*(?:\.[A-Z]\w*)+(?:Exception|Error)(?: \(0x[0-9A-Fa-f]+\))?:.*"
            r"|\[\w*(?:Exception|Error) \(0x[0-9A-Fa-f]+\)(?::[^\]]*)?\]",
            re.MULTILINE,
        ),
    ),
    (
        "Node.js",
        # V8 frames: "    at Object.<anonymous> (/app/server.js:10:15)"
        # or the anonymous form "    at /app/server.js:10:15".
        # The location must contain a letter or a path separator so an indented
        # timestamp line ("    at 12:30:45") is not mistaken for a frame.
        re.compile(
            r"^\s+at (?:async )?(?:[\w.$<>\[\] ]+ )?\(?"
            r"(?=[^\s()]*[A-Za-z\\/])[^\s()]+:\d+:\d+\)?\s*$",
            re.MULTILINE,
        ),
    ),
    (
        "Ruby",
        # "/app/foo.rb:12:in `bar'" (also the "from " continuation lines).
        re.compile(r"^\s*(?:from )?\S*\.rb:\d+:in [`']", re.MULTILINE),
    ),
    (
        "Go",
        # Runtime panic dump: "goroutine 1 [running]:".
        re.compile(r"goroutine \d+ \[\w+\]:"),
    ),
]

# An error message often echoes the input that caused it (.NET "Unclosed quotation mark after the
# character string '<payload>'", PHP "include(<payload>): failed to open stream"). Keying on the
# whole evidence would then report the same error once per payload sent by an attack module, so
# these extract what identifies the error itself.
DOTNET_EXCEPTION_TYPE = re.compile(r"\[?([\w.]*(?:Exception|Error))(?: \(0x[0-9A-Fa-f]+\))?:")
# Exception.ToString() chains wrapped exceptions inline: "Outer: ... ---> Inner: ..."
DOTNET_INNER_EXCEPTION = re.compile(r"\s*---(?:>|&gt;)\s*")
PHP_ERROR_LOCATION = re.compile(r".* in (.+?\.php)(?:\(\d+\))? on line (\d+)$", re.DOTALL | re.IGNORECASE)
GOROUTINE_ID = re.compile(r"\d+")


def _dedup_key(label: str, evidence: str, request: Request) -> tuple:
    if label == ".NET":
        # The innermost exception is the one carrying the actual error. Its type alone would merge
        # unrelated errors raised on different pages, so the endpoint is part of the key: all the
        # payloads sent to an endpoint still collapse into one finding.
        exception = DOTNET_EXCEPTION_TYPE.match(DOTNET_INNER_EXCEPTION.split(evidence)[-1])
        if exception:
            location = urlsplit(request.url)
            return label, location.netloc, location.path, exception.group(1)
    elif label == "PHP":
        location = PHP_ERROR_LOCATION.match(evidence)
        if location:
            return label, location.group(1), location.group(2)
    elif label == "Go":
        # The goroutine number changes with the connection serving the request
        return label, GOROUTINE_ID.sub("N", evidence)
    # Stack frames, banners...: nothing echoed from the request
    return label, evidence


class ModuleStacktraceDisclosure(PassiveModule):
    """
    Detects framework/language stack traces and unhandled error messages
    leaked in HTTP responses (Python, PHP, Java, .NET, Node.js, Ruby, Go).
    Such output reveals sensitive information about the application internals.
    """

    name = "stacktrace_disclosure"
    scan_attack_responses = True

    def analyze(
        self, request: Request, response: Response
    ) -> Generator[VulnerabilityInstance, Any, None]:
        if not response.content:
            return

        if not any(
            t in response.type for t in ("text/html", "text/plain", "application/json")
        ):
            return

        for label, pattern in STACKTRACE_PATTERNS:
            match = pattern.search(response.content)
            if not match:
                continue

            evidence = match.group().strip()
            # Computed before truncation, which could cut off the PHP file and line
            key = _dedup_key(label, evidence, request)
            # Keep the reported snippet short; a frame is enough to prove the leak.
            if len(evidence) > 150:
                evidence = evidence[:150] + "..."

            if not self.should_report(key, StacktraceDisclosureFinding):
                continue

            log_orange(
                f"Potential {label} stack trace disclosure in {request.url}: {evidence}"
            )
            yield VulnerabilityInstance(
                finding_class=StacktraceDisclosureFinding,
                request=request,
                response=response,
                info=f"Response discloses a {label} stack trace or error message: {evidence}",
                severity=MEDIUM_LEVEL,
            )
