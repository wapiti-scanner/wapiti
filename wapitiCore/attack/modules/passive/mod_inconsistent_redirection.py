from typing import Generator, Any, Optional
from urllib.parse import urlparse

from wapitiCore.attack.modules.passive.base import PassiveModule
from wapitiCore.definitions.inconsistent_redirection import InconsistentRedirectionFinding
from wapitiCore.language.vulnerability import MEDIUM_LEVEL
from wapitiCore.main.log import log_orange

from wapitiCore.model.vulnerability import VulnerabilityInstance
from wapitiCore.net import Request, Response
from wapitiCore.parsers.html_parser import Html


def _resource_key(url: str) -> tuple:
    """Normalized identity of a URL, ignoring the scheme and a trailing slash.

    Server-generated redirect boilerplate often links to the destination with a
    different scheme (an http:// link while the Location header is https://) or
    with/without a trailing slash — most commonly for directory redirects that
    only append a slash to the path. Those differences are not meaningful here."""
    parts = urlparse(url)
    return parts.netloc.lower(), parts.path.rstrip("/"), parts.query


def _points_to_redirection_target(link: str, target: Optional[str]) -> bool:
    """True when a body link is just the redirection destination itself,
    even if it differs only by scheme (http/https) or a trailing slash."""
    if not target:
        return False
    return _resource_key(link) == _resource_key(target)


class ModuleInconsistentRedirection(PassiveModule):
    """
    Detects when a 3xx redirection response also returns meaningful HTML content
    (like links or forms), which may confuse clients and pose security risks.
    """

    name = "inconsistent_redirection"

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
        if not self.should_report(response.md5):
            return

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
