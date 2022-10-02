import re
from typing import List

RE_JS_REDIR = re.compile(
    r"\b(window\.|document\.|top\.|self\.)?location(\.href)?\s*=\s*(\"|')([^'\"]+)\3\s*(;|}|$)"
)


def extract_js_redirections(text: str) -> List[str]:
    redirections = set()
    for search in re.finditer(RE_JS_REDIR, text):
        redirections.add(search.group(4))
    return list(redirections)
