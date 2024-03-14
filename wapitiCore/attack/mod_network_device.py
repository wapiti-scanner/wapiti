from asyncio import Event
from typing import Optional

from wapitiCore.attack.network_devices.mod_harbor import ModuleHarbor
from wapitiCore.attack.network_devices.mod_citrix import ModuleCitrix
from wapitiCore.attack.network_devices.mod_forti import ModuleForti
from wapitiCore.attack.network_devices.mod_ubika import ModuleUbika
from wapitiCore.attack.attack import Attack
from wapitiCore.net import Request
from wapitiCore.net.response import Response


class ModuleNetworkDevice(Attack):
    """Base class for detecting version."""
    name = "network_device"

    async def must_attack(self, request: Request, response: Optional[Response] = None):
        if self.finished:
            return False

        if request.method == "POST":
            return False

        return request.url == await self.persister.get_root_url()

    async def attack(self, request: Request, response: Optional[Response] = None):
        self.finished = True
        request_to_root = Request(request.url)
        modules_list = [ModuleUbika, ModuleForti, ModuleHarbor, ModuleCitrix]
        for module in modules_list:
            mod = module(
                self.crawler, self.persister, self.options, Event(), self.crawler_configuration
            )
            await mod.attack(request_to_root)
