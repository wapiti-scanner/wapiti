TYPE = "vulnerability"

NAME = "Stored HTML Injection"

SHORT_NAME = "Stored HTML Injection"

WSTG_CODE = ["WSTG-CLNT-03"]

DESCRIPTION = (
    "HTML injection is a type of injection vulnerability that occurs when a user is able to control an input point "
    "and is able to inject arbitrary HTML code into a vulnerable web page. "
    "This vulnerability can allow the attacker to modify the page content seen by the victims."
)

SOLUTION = (
    "Avoid Raw HTML Rendering: Whenever possible, avoid directly rendering user-generated content as raw HTML. "
    "Instead, use built-in templating systems or libraries that automatically escape user input by default, "
    "such as Django's template engine or AngularJS's ng-bind directive. "
    "With PHP you can use the htmlspecialchars() function to convert special characters to their corresponding "
    "HTML entities."
)

REFERENCES = (
    {
        "title": "OWASP: Testing for HTML Injection",
        "url": (
            "https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/"
            "11-Client_Side_Testing/03-Testing_for_HTML_Injection"
        )
    },
    {
        "title": "IMPERVA: HTML Injection",
        "url": "https://www.imperva.com/learn/application-security/html-injection/",
    },
    {
        "title": "HackTricks: Dangling Markup - HTML scriptless injection",
        "url": "https://book.hacktricks.xyz/pentesting-web/dangling-markup-html-scriptless-injection"
    },
)
