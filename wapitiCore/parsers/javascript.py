import re
from typing import List

RE_JS_REDIR = re.compile(
    r"\b(window\.|document\.|top\.|self\.)?location(\.href)?\s*=\s*(\"|')([^'\"]+)\3\s*(;|}|$)"
)

RE_WINDOW_OPEN = re.compile(
    r"\bwindow\.open\(\s*(\"|')([^'\"]+)\1\s*\)"
)


def extract_js_redirections(text: str) -> List[str]:
    redirections = set()
    for search in re.finditer(RE_JS_REDIR, text):
        redirections.add(search.group(4))
    for search in re.finditer(RE_WINDOW_OPEN, text):
        redirections.add(search.group(2))
    return list(redirections)
