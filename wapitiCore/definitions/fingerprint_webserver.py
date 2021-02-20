from wapitiCore.language.language import _

TYPE = "vulnerability"

NAME = _("Fingerprint web server")
SHORT_NAME = NAME

DESCRIPTION = _(
    "The version of a web server can be identified due to the presence of its specific fingerprints."
)

SOLUTION = _(
    "This is only for informational purposes."
)

REFERENCES = [
    {
        "title": "OWASP: Fingerprint Web Server",
        "url": (
            "https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/"
            "01-Information_Gathering/02-Fingerprint_Web_Server.html"
        )
    }
]
