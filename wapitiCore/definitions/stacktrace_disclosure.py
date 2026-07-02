from typing import List

from wapitiCore.definitions.base import FindingBase


class StacktraceDisclosureFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "Stack Trace Disclosure"

    @classmethod
    def description(cls) -> str:
        return (
            "The application response discloses a stack trace or an unhandled "
            "error message. Such output may reveal the technology stack, library "
            "versions, internal file paths, SQL queries or fragments of source "
            "code, helping an attacker to fingerprint the application and prepare "
            "further attacks."
        )

    @classmethod
    def references(cls) -> list:
        return [
            {
                "title": "OWASP: Improper Error Handling",
                "url": (
                    "https://owasp.org/www-community/Improper_Error_Handling"
                ),
            },
            {
                "title": (
                    "OWASP WSTG: Testing for Improper Error Handling"
                ),
                "url": (
                    "https://owasp.org/www-project-web-security-testing-guide/latest/"
                    "4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/"
                    "01-Testing_For_Improper_Error_Handling"
                ),
            },
            {
                "title": "CWE-209: Generation of Error Message Containing Sensitive Information",
                "url": "https://cwe.mitre.org/data/definitions/209.html",
            },
            {
                "title": "CWE-550: Server-generated Error Message Containing Sensitive Information",
                "url": "https://cwe.mitre.org/data/definitions/550.html",
            },
        ]

    @classmethod
    def solution(cls) -> str:
        return (
            "Disable verbose error reporting and debug mode in production. "
            "Catch and handle exceptions so that stack traces are logged on the "
            "server side only and never returned to the client. Return generic "
            "error pages to end users."
        )

    @classmethod
    def short_name(cls) -> str:
        return "Stack Trace Disclosure"

    @classmethod
    def type(cls) -> str:
        return "vulnerability"

    @classmethod
    def wstg_code(cls) -> List[str]:
        return ["WSTG-ERRH-02"]
