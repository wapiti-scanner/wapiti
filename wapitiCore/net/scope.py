from typing import Iterable, Union, Set
from urllib.parse import urlparse

from tld import get_fld
from tld.exceptions import TldDomainNotFound

from wapitiCore.net.web import Request


class Scope:
    def __init__(self, base_request: Request, scope: str):
        self._scope: str = scope
        self._base_request: Request = base_request

    @property
    def name(self) -> str:
        return self._scope

    def check(self, resource: Union[Request, str]) -> bool:
        if self._scope == "punk":
            # Life is short
            return True

        if isinstance(resource, Request):
            if self._scope == "folder":
                return resource.url.startswith(self._base_request.path)
            if self._scope == "page":
                return resource.path == self._base_request.path
            if self._scope == "url":
                return resource.url == self._base_request.url
            # domain
            try:
                return get_fld(resource.url) == get_fld(self._base_request.url)
            except TldDomainNotFound:
                return resource.hostname == self._base_request.hostname
        else:
            if not resource:
                return False

            if self._scope == "folder":
                return resource.startswith(self._base_request.path)
            if self._scope == "page":
                return resource.split("?")[0] == self._base_request.path
            if self._scope == "url":
                return resource == self._base_request.url
            # domain
            try:
                return get_fld(resource) == get_fld(self._base_request.url)
            except TldDomainNotFound:
                return urlparse(resource).netloc == self._base_request.hostname

    def filter(self, resources: Iterable[Union[Request, str]]) -> Set[Union[Request, str]]:
        return {resource for resource in resources if self.check(resource)}
