from typing import Iterable, Union, Set
from urllib.parse import urlparse

from tld import get_fld
from tld.exceptions import TldDomainNotFound

from wapitiCore.net import Request


def is_same_domain(url: str, request: Request) -> bool:
    url_parts = urlparse(url)
    try:
        return get_fld(url) == get_fld(request.url)
    except TldDomainNotFound:
        # Internal domain of IP
        # Check hostname instead of netloc to allow other ports
        return url_parts.hostname == request.hostname


class Scope:
    def __init__(self, base_request: Request, scope: str):
        self._scope: str = scope
        self._base_request: Request = base_request

    @property
    def name(self) -> str:
        return self._scope

    def check(self, resource: Union[Request, str]) -> bool:
        if not resource:
            return False

        if self._scope == "punk":
            # Life is short
            return True

        if isinstance(resource, Request):
            url = resource.url
        else:
            url = resource

        if self._scope == "domain":
            return is_same_domain(url, self._base_request)

        if self._scope == "folder":
            return url.startswith(self._base_request.path)

        if self._scope == "page":
            return url.split("?")[0] == self._base_request.path

        # URL
        return url == self._base_request.url

    def filter(self, resources: Iterable[Union[Request, str]]) -> Set[Union[Request, str]]:
        return {resource for resource in resources if self.check(resource)}
