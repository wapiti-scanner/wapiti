from typing import List

from wapitiCore.definitions.base import FindingBase


class InformationDisclosureFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "Information Disclosure - Full Path"

    @classmethod
    def description(cls) -> str:
        return (
            "The application response discloses full system paths. "
            "This information can help attackers understand the server "
            "environment, directory structure, and operating system, "
            "which can facilitate further attacks."
        )

    @classmethod
    def references(cls) -> list:
        return [
            {
                "title": "OWASP: Information Leakage",
                "url": (
                    "https://owasp.org/www-project-web-security-testing-guide/latest/"
                    "4-Web_Application_Security_Testing/01-Information_Gathering/"
                    "05-Review_Web_Page_Content_for_Information_Leakage"
                ),
            },
            {
                "title": "CWE-209: Generation of Error Message Containing Sensitive Information",
                "url": "https://cwe.mitre.org/data/definitions/209.html",
            },
            {
                "title": "WASC-13: Information Leakage",
                "url": "http://projects.webappsec.org/w/page/13246936/Information%20Leakage",
            },
        ]

    @classmethod
    def solution(cls) -> str:
        return (
            "Ensure that error messages and application responses do not disclose "
            "full filesystem paths or other sensitive system information. "
            "Use generic error messages for end users and log detailed errors "
            "only on the server side."
        )

    @classmethod
    def short_name(cls) -> str:
        return "Information Disclosure"

    @classmethod
    def type(cls) -> str:
        return "vulnerability"

    @classmethod
    def wstg_code(cls) -> List[str]:
        return ["WSTG-ERRH-01"]
