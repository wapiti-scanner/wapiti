import html
import json
import re
from bisect import bisect_right
from itertools import accumulate
from typing import Generator, Any, Dict, Iterator, List, Tuple

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


# A raw body that is not JSON (XML, SOAP, text...) is split on markup delimiters to get its fields.
RAW_BODY_DELIMITERS = re.compile(r"[<>\"'\r\n]")
# "../", "..\" and filter-bypass forms such as "....//" of a directory traversal payload
TRAVERSAL = re.compile(r"\.{2,}[/\\]+")
# file:// wrapper (mod_file) or XXE entity (mod_xxe): runtimes report the local path, not the URL
FILE_URL = re.compile(r"file://([^\s\"'<>]+)", re.IGNORECASE)
# Uploaded files whose content is a document the server may parse (mod_xxe uploads XML)
TEXT_UPLOAD = re.compile(r"xml|svg|text|json", re.IGNORECASE)
# How htmlspecialchars(), html.escape(), HttpUtility.HtmlEncode()... write a single quote
HTML_APOSTROPHES = ("'", "&#039;", "&#x27;", "&#39;", "&apos;")
# The Windows branch of PATH_PATTERN also swallows the punctuation following the path
WINDOWS_PATH_TRAILER = ".,;:)]}"


def _json_strings(document: Any) -> Iterator[str]:
    """Every string (key or value) of a decoded JSON document. Iterative: no recursion limit."""
    stack = [document]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            yield item
        elif isinstance(item, dict):
            stack.extend(item.keys())
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)


def _body_fields(body: str, is_json: bool) -> List[str]:
    """Fields of a raw request body or uploaded document. The body as a whole is almost never
    written back, so comparing against it would treat an API echoing a single field as a disclosure."""
    if is_json:
        try:
            return list(_json_strings(json.loads(body)))
        except (ValueError, RecursionError):
            pass  # Declared as JSON but isn't: split it like any other raw body
    values = []
    for fragment in RAW_BODY_DELIMITERS.split(body):
        fragment = fragment.strip()
        if fragment:
            values.append(fragment)
            # XML character references are decoded by the server before the value is used
            values.append(html.unescape(fragment))
    return values


def _sent_values(request: Request) -> List[str]:
    """Values the client itself sent in the request.

    Covers parameter values and names (a query string injection like ``?/etc/passwd`` is parsed as
    a valueless parameter name), the fields of a raw JSON/XML body, uploaded file names and the
    fields of uploaded text documents.
    """
    values = []
    for key, value in request.get_params_ref:
        values.extend((key, value))
    post_params = request.post_params_ref
    if isinstance(post_params, list):
        for key, value in post_params:
            values.extend((key, value))
    elif isinstance(post_params, str) and post_params:
        values.extend(_body_fields(post_params, request.is_json))
    for key, file_value in request.file_params_ref:
        values.append(key)
        if not isinstance(file_value, (list, tuple)) or not file_value:
            continue
        values.append(file_value[0])
        if len(file_value) > 2 and isinstance(file_value[1], bytes) and TEXT_UPLOAD.search(str(file_value[2])):
            values.extend(_body_fields(file_value[1].decode(errors="replace"), "json" in str(file_value[2])))
    return [value for value in dict.fromkeys(values) if isinstance(value, str) and value]


def _resolved_targets(value: str) -> List[str]:
    """Absolute paths a payload points to, as the server reports them once it resolved the payload
    (target of a traversal, local path of a file:// URL, file name without its NTFS stream suffix).
    Windows reports them with backslashes, and a traversal target without its drive letter."""
    targets = []
    if TRAVERSAL.search(value):
        targets.append("/" + TRAVERSAL.split(value)[-1].lstrip("/\\"))
    for url_path in FILE_URL.findall(value):
        targets.append(url_path)
        if re.match(r"/[A-Za-z]:", url_path):  # file:///C:/...
            targets.append(url_path[1:])
    if "::$" in value:
        targets.append(value.split("::$", 1)[0])
    if re.match(r"[A-Za-z]:/", value):  # C:/Windows/...
        targets.append(value)
    return targets + [target.replace("/", "\\") for target in targets if "/" in target]


def _html_escaped(value: str) -> List[str]:
    """value as written by htmlspecialchars(), html.escape(), HttpUtility.HtmlEncode()..."""
    if not any(char in value for char in "&<>\"'"):
        return []
    escaped = value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return [
        escaped.replace('"', quote).replace("'", apostrophe)
        for quote in ('"', "&quot;")
        for apostrophe in HTML_APOSTROPHES
    ]


def _renderings(value: str) -> List[str]:
    """Forms under which the server may write a sent value back into the body."""
    forms = [value]
    if "\0" in value:
        # Most runtimes either cut a string at the NUL byte (C strings) or drop the byte
        forms.append(value.split("\0", 1)[0])
        forms.append(value.replace("\0", ""))
    for form in list(forms):
        forms.extend(_resolved_targets(form))
    forms.append(value.strip())
    # Spaces written back as "+" (form-encoded link), quotes escaped by addslashes() / magic quotes
    forms.append(value.replace(" ", "+"))
    forms.append(re.sub(r"([\\'\"])", r"\\\1", value).replace("\0", "\\0"))
    # Written into a JSON string: quotes, backslashes and control characters are escaped
    forms.append(json.dumps(value)[1:-1])
    forms.extend(_html_escaped(value))
    return [form for form in dict.fromkeys(forms) if form]


class _Reflections:
    """Where the values sent in a request are written back in the body of its response.

    A path found in the body is an echo only if it lies inside a copy of one complete sent value:
    the same path elsewhere in the body (a stack trace next to the echoed parameter) is still a
    disclosure. The one ambiguous case is a sent value that *is* exactly the path (or resolves to
    it): every occurrence of it is then treated as an echo, as it can't be told apart from a
    disclosure.

    The copies of each value are searched once per response and each path is then answered with
    a binary search, so a body echoing a long value full of paths stays linear.
    """

    def __init__(self, request: Request, content: str):
        self._content = content
        self._forms = list(dict.fromkeys(form for value in _sent_values(request) for form in _renderings(value)))
        # A path can't span a line break: cheap pre-filter before looking for copies
        self._text = "\n".join(self._forms)
        self._copies: Dict[str, List[int]] = {}
        self._covered: Dict[str, Tuple[List[int], List[int]]] = {}

    def _copies_of(self, form: str) -> List[int]:
        if form not in self._copies:
            positions = []
            position = self._content.find(form)
            while position != -1:
                positions.append(position)
                position = self._content.find(form, position + 1)
            self._copies[form] = positions
        return self._copies[form]

    def contains(self, start: int, evidence: str) -> bool:
        if evidence not in self._covered:
            # Sorted (start, end) spans of the copies of every sent value containing this path
            spans = sorted(
                (position, position + len(form))
                for form in (self._forms if evidence in self._text else ())
                if evidence in form
                for position in self._copies_of(form)
            )
            self._covered[evidence] = (
                [span_start for span_start, __ in spans],
                list(accumulate((span_end for __, span_end in spans), max)),
            )
        starts, furthest_ends = self._covered[evidence]
        # Among the copies starting at or before the path, does one reach its end?
        index = bisect_right(starts, start) - 1
        return index >= 0 and furthest_ends[index] >= start + len(evidence)


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
        content = response.content
        if not content:
            return

        if not any(
            t in response.type for t in ("text/html", "text/plain", "application/json")
        ):
            return

        reflections = None
        for match in PATH_PATTERN.finditer(content):
            evidence = match.group()
            if not _is_realistic_path(evidence):
                continue

            core = evidence
            is_windows = evidence[1:3] == ":\\"
            if is_windows:
                core = core.split("&", 1)[0].rstrip(WINDOWS_PATH_TRAILER)
            core = core.rstrip(".")

            if reflections is None:
                reflections = _Reflections(request, content)
            if reflections.contains(match.start(), core):
                continue
            # A traversal resolved by Windows comes back with a drive letter it didn't have
            if is_windows and reflections.contains(match.start() + 2, core[2:]):
                continue

            if not self.should_report(core, InformationDisclosureFinding):
                continue

            log_orange(f"Potential full path disclosure in {request.url}: {evidence}")
            yield VulnerabilityInstance(
                finding_class=InformationDisclosureFinding,
                request=request,
                response=response,
                info=f"Response contains potential system path: {evidence}",
                severity=LOW_LEVEL,
            )
