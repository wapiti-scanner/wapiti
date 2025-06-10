from typing import List

from wapitiCore.definitions.base import FindingBase


class InconsistentRedirectionFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "Inconsistent Redirection"

    @classmethod
    def description(cls) -> str:
        return (
            "An HTTP 3xx redirection response should typically contain only minimal content (or none), "
            "as clients are expected to follow the Location header. "
            "However, this response also contains HTML content (such as links or forms). "
            "This may confuse clients, expose unintended information, or allow attackers "
            "to craft malicious redirections."
        )

    @classmethod
    def references(cls) -> list:
        return [
            {
                "title": "ZAP Alert 10044-1: Inconsistent Redirection",
                "url": "https://www.zaproxy.org/docs/alerts/10044-1/",
            },
            {
                "title": "MDN: HTTP Redirections",
                "url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections",
            },
            {
                "title": "WSTG: Review Webpage Content for Information Leakage",
                "url": (
                    "https://owasp.org/www-project-web-security-testing-guide/v42/"
                    "4-Web_Application_Security_Testing/01-Information_Gathering/"
                    "05-Review_Webpage_Content_for_Information_Leakage"
                ),
            },
        ]

    @classmethod
    def solution(cls) -> str:
        return (
            "Ensure that 3xx HTTP responses only return the appropriate redirection headers and do not include "
            "unnecessary HTML content. If user feedback is required, provide a clear message without interactive "
            "elements (like links or forms). Always rely on the Location header for redirection logic."
        )

    @classmethod
    def short_name(cls) -> str:
        return cls.name()

    @classmethod
    def type(cls) -> str:
        return "vulnerability"

    @classmethod
    def wstg_code(cls) -> List[str]:
        return ["WSTG-INFO-05"]
