
TYPE = "vulnerability"

NAME = ("Spring4Shell")
SHORT_NAME = NAME

WSTG_CODE = ["WSTG-INPV-11"]

DESCRIPTION = (
    "A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE)"
    "via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment."
    "If the application is deployed as a Spring Boot executable jar, i.e. the default,"
    "it is not vulnerable to the exploit. However, the nature of the vulnerability is more general,"
    "and there may be other ways to exploit it."
)

SOLUTION = (
    "Users of affected versions should apply the following mitigation: 5.3.x users should upgrade to 5.3.18+,"
    "5.2.x users should upgrade to 5.2.20+. No other steps are necessary."
    "There are other mitigation steps for applications that cannot upgrade to the above versions."
)

REFERENCES = [
    {
        "title": "CYBERWATCH: Spring4Shell CVE-2022-22965",
        "url": (
            "https://cyberwatch.fr/cve/spring4shell-tout-savoir-sur-la-vulnerabilite-0-day-liee-a-java-spring/"
        )
    },
    {
        "title": "VMWARE: CVE-2022-22965 Detail",
        "url": "https://tanzu.vmware.com/security/cve-2022-22965"
    },
    {
        "title": "MITRE: CVE-2022-22965",
        "url": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-22965"
    },
    {
        "title": "OWASP: Code Injection",
        "url": (
            "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/"
            "07-Input_Validation_Testing/11-Testing_for_Code_Injection"
        )
    }
]
