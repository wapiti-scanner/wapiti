from httpx import RequestError

from wapitiCore.attack.attack import Attack
from wapitiCore.net.web import Request
from wapitiCore.language.vulnerability import MEDIUM_LEVEL, _
from wapitiCore.definitions.http_post import NAME


# This module check the security of transported credentials of login forms
class mod_http_post(Attack):
    """Check if credentials are transported on an encrypted channel."""
    name = "http_post"

    async def must_attack(self, request: Request):
        # We leverage the fact that the crawler will fill password entries with a known placeholder
        if "https://" in request.url:
            return False

        return True

    async def attack(self, request: Request):
        
        if "Letm3in_" not in request.encoded_data + request.encoded_params:
            return
        self.finished = True

        self.log_red(NAME)
        self.log_red(request)
        self.log_red("Credentials transported over an Unencrypted Channel on :  {0}".format(request.url))

        await self.add_vuln_medium(
            request_id=request.path_id,
            category=NAME,
            request=request,
            info=_("Credentials transported over an Unencrypted Channel on :  {0}").format(request.url)
        )
