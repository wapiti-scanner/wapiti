import re
from typing import Generator, Any

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
        # ASP.NET Yellow Screen of Death and CLR stack frames.
        re.compile(
            r"Server Error in '.*?' Application"
            r"|\[\w*(?:Exception|Error)(?::[^\]]*)?\]"
            r"|^\s*at [\w.<>+]+\(.*?\) in .+?:line \d+",
            re.MULTILINE,
        ),
    ),
    (
        "Node.js",
        # V8 frames: "    at Object.<anonymous> (/app/server.js:10:15)"
        # or the anonymous form "    at /app/server.js:10:15".
        re.compile(
            r"^\s+at (?:async )?(?:[\w.$<>\[\] ]+ )?\(?"
            r"[^\s()]+:\d+:\d+\)?\s*$",
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


class ModuleStacktraceDisclosure:
    """
    Detects framework/language stack traces and unhandled error messages
    leaked in HTTP responses (Python, PHP, Java, .NET, Node.js, Ruby, Go).
    Such output reveals sensitive information about the application internals.
    """

    name = "stacktrace_disclosure"

    def __init__(self):
        # Track already-reported (language, evidence) pairs across the scan.
        self._reported = set()

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
            # Keep the reported snippet short; a frame is enough to prove the leak.
            if len(evidence) > 150:
                evidence = evidence[:150] + "..."

            key = (label, evidence)
            if key in self._reported:
                continue
            self._reported.add(key)

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
