import re
from typing import Generator, Any, List

from wapitiCore.attack.modules.passive.base import PassiveModule
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
    r"(?:[^ \t\r\n<>'\"/]*/)*"
    r"(?:bin|usr|mnt|proc|sbin|dev|lib|tmp|opt|home|var|root|etc|Applications|Volumes|System|Users|Developer|Library)"
    r"/[\w./~-]*"
    r"|"
    # Windows absolute paths
    r"[A-Za-z]:\\(?:Program Files|Users|Windows|ProgramData|Progra~1)[^ \t\r\n<>'\"]*"
    r")",
    flags=re.IGNORECASE,
)

# A real disclosed filesystem path is short; giant matches are base64 / tokens
# (e.g. an ASP.NET __VIEWSTATE) that merely happen to contain a "/keyword/"
# chunk. These bounds discard such noise without trying to base64-decode.
MAX_PATH_LENGTH = 255
# Path components are short and human-readable. base64/hash chunks between two
# slashes are long, so a very long component is a strong noise signal.
MAX_SEGMENT_LENGTH = 40
# Below this length a component is too short to confidently call base64 noise.
MIN_BASE64_SEGMENT_LENGTH = 24


def _looks_like_base64_segment(segment: str) -> bool:
    """A long component mixing upper-case, lower-case and digits looks like a
    base64/token chunk rather than a directory or file name. A hex hash or a
    UUID (lower-case + digits, no upper-case) is intentionally *not* flagged."""
    if len(segment) < MIN_BASE64_SEGMENT_LENGTH:
        return False
    return (
        any(c.isupper() for c in segment)
        and any(c.islower() for c in segment)
        and any(c.isdigit() for c in segment)
    )


def _is_realistic_path(candidate: str) -> bool:
    """Heuristics to tell an actual system path from base64/token noise that
    happens to match PATH_PATTERN. No decoding is attempted."""
    if len(candidate) > MAX_PATH_LENGTH:
        return False
    # "=" is base64 padding and never appears in a normal filesystem path.
    if "=" in candidate:
        return False
    return not any(
        len(segment) > MAX_SEGMENT_LENGTH or _looks_like_base64_segment(segment)
        for segment in re.split(r"[/\\]", candidate)
    )


def _sent_values(request: Request) -> List[str]:
    """Values the client itself sent in the request (query string, body, uploaded file names).

    A path found in the response that comes from one of them is merely echoed back (e.g. a
    mod_file payload like /etc/passwd reflected by a search page), not disclosed by the server.
    """
    values = [value for __, value in request.get_params_ref if value]
    post_params = request.post_params_ref
    if isinstance(post_params, list):
        values.extend(value for __, value in post_params if value)
    elif post_params:
        # Raw body (JSON, XML...)
        values.append(post_params)
    values.extend(
        file_value[0] for __, file_value in request.file_params_ref
        if isinstance(file_value, (list, tuple)) and file_value and isinstance(file_value[0], str)
    )
    return values


class ModuleInformationDisclosure(PassiveModule):
    """
    Detects disclosure of full system paths (Windows/Unix) in HTTP responses.
    Such paths may reveal sensitive information about the server environment.
    """

    name = "information_disclosure"
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

        sent_values = None
        for match in PATH_PATTERN.finditer(response.content):
            evidence = match.group()
            if not _is_realistic_path(evidence):
                continue

            if sent_values is None:
                sent_values = _sent_values(request)
            if any(evidence.rstrip(".") in value for value in sent_values):
                continue

            if not self.should_report(evidence.rstrip("."), InformationDisclosureFinding):
                continue

            log_orange(f"Potential full path disclosure in {request.url}: {evidence}")
            yield VulnerabilityInstance(
                finding_class=InformationDisclosureFinding,
                request=request,
                response=response,
                info=f"Response contains potential system path: {evidence}",
                severity=LOW_LEVEL,
            )
