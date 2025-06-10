from typing import Generator, Any

from wapitiCore.definitions.cleartext_password_submission import CleartextPasswordSubmissionFinding
from wapitiCore.language.vulnerability import HIGH_LEVEL
from wapitiCore.main.log import log_red

from wapitiCore.model.vulnerability import VulnerabilityInstance
from wapitiCore.net import Request, Response
from wapitiCore.parsers.html_parser import Html


class ModuleUnsecurePassword:
    """
    Detects passwords sent over a non-encrypted (TLS) channel
    """
    name = "unsecure_password"

    def __init__(self):
        self._known_vulnerable_forms = set()

    def analyze(self, request: Request, response: Response) ->  Generator[VulnerabilityInstance, Any, None]:
        page = Html(response.content, request.url)
        for form in page.iter_forms():
            if form.url.startswith("http://"):
                for field in form.fields:
                    if field.tag_type == "password":
                        form_identifier = (form.url, form.method.upper(), field.name)

                        if form_identifier in self._known_vulnerable_forms:
                            continue

                        self._known_vulnerable_forms.add(form_identifier)
                        log_red(
                            "Cleartext transmission of sensitive information: "
                            f"Password field '{field.name}' is sent over unencrypted connections from URL {request.url}"
                        )

                        yield VulnerabilityInstance(
                            finding_class=CleartextPasswordSubmissionFinding,
                            request=request,
                            response=response,
                            info=f"Password field {field.name} sent in clear text from URL {request.url}",
                            severity=HIGH_LEVEL,
                            parameter=field.name
                        )
