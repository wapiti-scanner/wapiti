from wapitiCore.language.language import _

TYPE = "vulnerability"

NAME = _("Reflected Cross Site Scripting")

SHORT_NAME = _("XSS")

WSTG_CODE = ["WSTG-INPV-01"]

DESCRIPTION = _(
    "Cross-site scripting (XSS) is a type of computer security vulnerability typically found in web applications "
    "which allow code injection by malicious web users into the web pages viewed by other users."
) + " " + _("Examples of such code include HTML code and client-side scripts.")

SOLUTION = _(
    "The best way to protect a web application from XSS attacks is ensure that the application performs validation of "
    "all headers, cookies, query strings, form fields, and hidden fields."
) + " " + _(
    "Encoding user supplied output in the server side can also defeat XSS vulnerabilities by preventing inserted "
    "scripts from being transmitted to users in an executable form."
) + " " + _(
    "Applications can gain significant protection from javascript based attacks by converting the following characters "
    "in all generated output to the appropriate HTML entity encoding:"
) + "<, >, &, ', (, ), #, %, ; , +, -"

REFERENCES = [
    {
        "title": "OWASP: Cross Site Scripting (XSS)",
        "url": "https://owasp.org/www-community/attacks/xss/"
    },
    {
        "title": "Wikipedia: Cross-site scripting",
        "url": "https://en.wikipedia.org/wiki/Cross-site_scripting"
    },
    {
        "title": "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        "url": "https://cwe.mitre.org/data/definitions/79.html"
    },
    {
        "title": "OWASP: Reflected Cross Site Scripting",
        "url": (
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/"
            "07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting"
        )
    }
]
