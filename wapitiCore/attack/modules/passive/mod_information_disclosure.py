import re
from typing import Generator, Any

from wapitiCore.definitions.information_disclosure import InformationDisclosureFinding
from wapitiCore.language.vulnerability import LOW_LEVEL
from wapitiCore.main.log import log_orange

from wapitiCore.model.vulnerability import VulnerabilityInstance
from wapitiCore.net import Request, Response

PATH_PATTERN = re.compile(
    r"(?:\A|(?<![\w:/\\.-]))"  # zero-width guard: start-of-string or not preceded by word/':', '/', '\', '.', '-'
    r"("
    # Unix-like absolute paths, allowing extra leading segments (e.g. /hj/var/...)
    # and explicitly forbidding schemes like "http://", "https://", etc. right after the slash.
    r"/(?![^ \t\r\n<>'\"]*://)"
    r"(?:[^ \t\r\n<>'\"]*/)*"
    r"(?:bin|usr|mnt|proc|sbin|dev|lib|tmp|opt|home|var|root|etc|Applications|Volumes|System|Users|Developer|Library)"
    r"/[\w./~-]*"
    r"|"
    # Windows absolute paths
    r"[A-Za-z]:\\(?:Program Files|Users|Windows|ProgramData|Progra~1)[^ \t\r\n<>'\"]*"
    r")",
    flags=re.IGNORECASE,
)


class ModuleInformationDisclosure:
    """
    Detects disclosure of full system paths (Windows/Unix) in HTTP responses.
    Such paths may reveal sensitive information about the server environment.
    """

    name = "information_disclosure"

    def __init__(self):
        # track already-reported paths
        self._reported_paths = set()

    def analyze(
        self, request: Request, response: Response
    ) -> Generator[VulnerabilityInstance, Any, None]:
        if not response.content:
            return

        if not any(
            t in response.type for t in ("text/html", "text/plain", "application/json")
        ):
            return

        for match in PATH_PATTERN.finditer(response.content):
            evidence = match.group()
            if evidence.rstrip(".") in self._reported_paths:
                continue

            self._reported_paths.add(evidence.rstrip("."))

            log_orange(f"Potential full path disclosure in {request.url}: {evidence}")
            yield VulnerabilityInstance(
                finding_class=InformationDisclosureFinding,
                request=request,
                response=response,
                info=f"Response contains potential system path: {evidence}",
                severity=LOW_LEVEL,
            )
