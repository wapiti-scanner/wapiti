import re
from typing import List

# Delay threshold in milliseconds - redirects delayed by 3+ seconds are not exploitable
# as users have time to cancel the navigation
EXPLOIT_DELAY_THRESHOLD = 3000

RE_JS_REDIR = re.compile(
    r"\b(window\.|document\.|top\.|self\.)?location(\.href)?\s*=\s*(\"|')([^'\"]+)\3\s*(;|}|$)"
)

RE_WINDOW_OPEN = re.compile(
    r"\bwindow\.open\(\s*(\"|')([^'\"]+)\1\s*\)"
)

# Regex to detect setTimeout wrapping with delay parameter
# Matches: setTimeout(function(){...}, delay) or setTimeout(() => {...}, delay) or setTimeout("...", delay)
RE_SETTIMEOUT = re.compile(
    r"setTimeout\s*\(\s*(?:function\s*\([^)]*\)\s*\{|(?:\([^)]*\)|[a-zA-Z_$][a-zA-Z0-9_$]*)\s*=>\s*\{|['\"])"
    r"(.*?)"  # Capture content
    r"(?:\}|['\"])\s*,\s*(\d+)\s*\)",  # Capture delay in milliseconds
    re.DOTALL
)


def is_delayed_redirect(text: str, match_start: int, match_end: int) -> bool:
    """Check if a redirect is wrapped in setTimeout with delay >= threshold.

    Args:
        text: Full JavaScript text
        match_start: Start position of the redirect match
        match_end: End position of the redirect match

    Returns:
        True if redirect is delayed by >= EXPLOIT_DELAY_THRESHOLD milliseconds
    """
    # Search for setTimeout patterns that could contain this redirect
    for timeout_match in re.finditer(RE_SETTIMEOUT, text):
        timeout_start = timeout_match.start()
        timeout_end = timeout_match.end()

        # Check if the redirect is inside this setTimeout
        if timeout_start < match_start and match_end < timeout_end:
            try:
                delay = int(timeout_match.group(2))
                if delay >= EXPLOIT_DELAY_THRESHOLD:
                    return True
            except (ValueError, IndexError):
                # If we can't parse the delay, assume it's not delayed
                continue

    return False


def extract_js_redirections(text: str) -> List[str]:
    """Extract JavaScript redirection URLs, filtering out delayed redirects.

    This function finds location.href assignments and window.open calls,
    but excludes redirects wrapped in setTimeout with delays >= 3 seconds,
    as these are not exploitable (users have time to cancel).

    Args:
        text: JavaScript code to analyze

    Returns:
        List of redirection URLs (only immediate or short-delay redirects)
    """
    redirections = set()

    # Check location.href redirections
    for search in re.finditer(RE_JS_REDIR, text):
        # Skip if this redirect is delayed by 3+ seconds
        if not is_delayed_redirect(text, search.start(), search.end()):
            redirections.add(search.group(4))

    # Check window.open calls (these are not typically delayed)
    for search in re.finditer(RE_WINDOW_OPEN, text):
        redirections.add(search.group(2))

    return list(redirections)
