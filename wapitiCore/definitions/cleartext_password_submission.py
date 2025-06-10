from typing import List

from wapitiCore.definitions import FindingBase


class CleartextPasswordSubmissionFinding(FindingBase):
    @classmethod
    def name(cls) -> str:
        return "Cleartext Submission of Password"

    @classmethod
    def description(cls) -> str:
        return (
            "A password was submitted to the application using an unencrypted HTTP connection. "
            "This makes the password vulnerable to eavesdropping by attackers on the network, "
            "potentially leading to account compromise or further attacks."
        )

    @classmethod
    def references(cls) -> list:
        return [
            {
                "title": "PortSwigger: Cleartext submission of password",
                "url": "https://portswigger.net/kb/issues/00300100_cleartext-submission-of_password"
            },
            {
                "title": "OWASP: Transport Layer Protection",
                "url": (
                    "https://owasp.org/www-project-web-security-testing-guide/stable/"
                    "4-Web_Application_Security_Testing/04-Authentication_Testing/"
                    "01-Testing_for_Credentials_Transported_over_an_Encrypted_Channel"
                )
            },
            {
                "title": "CWE-319: Cleartext Transmission of Sensitive Information",
                "url": "https://cwe.mitre.org/data/definitions/319.html"
            }
        ]

    @classmethod
    def solution(cls) -> str:
        return (
            "Ensure that all password submissions and sensitive data transmissions "
            "are performed exclusively over HTTPS (HTTP Secure). "
            "Implement HSTS (HTTP Strict Transport Security) to enforce the use of HTTPS "
            "and prevent downgrades to HTTP."
        )

    @classmethod
    def short_name(cls) -> str:
        return "Cleartext Password"

    @classmethod
    def type(cls) -> str:
        return "vulnerability"

    @classmethod
    def wstg_code(cls) -> List[str]:
        # Le code WSTG le plus pertinent est lié à la protection de la couche transport.
        return ["WSTG-CONF-07"]
