from typing import Generator, Any

from wapitiCore.attack.modules.passive.base import PassiveModule
from wapitiCore.definitions.cleartext_password_submission import CleartextPasswordSubmissionFinding
from wapitiCore.language.vulnerability import HIGH_LEVEL
from wapitiCore.main.log import log_red

from wapitiCore.model.vulnerability import VulnerabilityInstance
from wapitiCore.net import Request, Response
from wapitiCore.parsers.html_parser import Html


class ModuleUnsecurePassword(PassiveModule):
    """
    Detects passwords sent over a non-encrypted (TLS) channel
    """
    name = "unsecure_password"

    def analyze(self, request: Request, response: Response) ->  Generator[VulnerabilityInstance, Any, None]:
        if "text/html" not in response.type:
            return

        page = Html(response.content, request.url)
        for form in page.iter_forms():
            if form.url.startswith("http://"):
                for field in form.fields:
                    if field.tag_type == "password":
                        form_identifier = (form.url, form.method.upper(), field.name)

                        if not self.should_report(form_identifier):
                            continue

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
