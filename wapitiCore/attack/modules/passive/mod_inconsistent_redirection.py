from typing import Generator, Any, Optional

from wapitiCore.definitions.inconsistent_redirection import InconsistentRedirectionFinding
from wapitiCore.language.vulnerability import MEDIUM_LEVEL
from wapitiCore.main.log import log_orange

from wapitiCore.model.vulnerability import VulnerabilityInstance
from wapitiCore.net import Request, Response
from wapitiCore.parsers.html_parser import Html


def _points_to_redirection_target(link: str, target: Optional[str]) -> bool:
    """True when a body link is just the redirection destination itself."""
    if target is None:
        return False
    return link.rstrip("/") == target.rstrip("/")


class ModuleInconsistentRedirection:
    """
    Detects when a 3xx redirection response also returns meaningful HTML content
    (like links or forms), which may confuse clients and pose security risks.
    """

    name = "inconsistent_redirection"

    def __init__(self):
        # Keep track of already-reported responses, by response MD5
        self._reported_hashes = set()

    def analyze(self, request: Request, response: Response) -> Generator[VulnerabilityInstance, Any, None]:
        if not response.is_redirect:
            return

        if "text/html" not in response.type:
            return

        if not response.content:
            return

        # Use Html parser to check if the body contains at least one link or form
        page = Html(response.content, request.url)
        forms = list(page.iter_forms())

        # The standard framework redirect body (ASP.NET/IIS "Object moved to
        # <a href="target">here</a>") only links to the redirection target
        # itself: that is expected boilerplate, not leaked content. Only the
        # links pointing *elsewhere* betray the real bug this module targets
        # (e.g. a PHP header() not followed by die() that still emits a page).
        target = response.redirection_url
        meaningful_links = [
            link for link in page.links
            if not _points_to_redirection_target(link, target)
        ]

        if not meaningful_links and not forms:
            return

        # Deduplicate with response MD5
        if response.md5 in self._reported_hashes:
            return

        self._reported_hashes.add(response.md5)

        log_orange(
            f"Redirection response at {request.url} contains HTML content with links/forms"
        )

        yield VulnerabilityInstance(
            finding_class=InconsistentRedirectionFinding,
            request=request,
            response=response,
            info="3xx redirection contains unexpected HTML body (links/forms)",
            severity=MEDIUM_LEVEL,
        )
