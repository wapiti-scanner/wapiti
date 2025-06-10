from typing import Generator, Any

from wapitiCore.definitions.inconsistent_redirection import InconsistentRedirectionFinding
from wapitiCore.language.vulnerability import MEDIUM_LEVEL
from wapitiCore.main.log import log_orange

from wapitiCore.model.vulnerability import VulnerabilityInstance
from wapitiCore.net import Request, Response
from wapitiCore.parsers.html_parser import Html


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
        if not page.links and not list(page.iter_forms()):
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
