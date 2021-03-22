from wapitiCore.language.language import _

TYPE = "vulnerability"

NAME = _("Fingerprint web application framework")
SHORT_NAME = NAME

DESCRIPTION = _(
    "The version of a web application framework can be identified due to the presence of its specific fingerprints."
)

SOLUTION = _(
    "This is only for informational purposes."
)

REFERENCES = [
    {
        "title": "OWASP: Fingerprint Web Application Framework",
        "url": (
            "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/"
            "01-Information_Gathering/08-Fingerprint_Web_Application_Framework.html"
        )
    }
]
