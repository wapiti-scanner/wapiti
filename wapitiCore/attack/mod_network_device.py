#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2024 Cyberwatch
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
from asyncio import Event
from typing import Optional

from wapitiCore.attack.network_devices.mod_checkpoint import ModuleCheckPoint
from wapitiCore.attack.network_devices.mod_citrix import ModuleCitrix
from wapitiCore.attack.network_devices.mod_forti import ModuleForti
from wapitiCore.attack.network_devices.mod_harbor import ModuleHarbor
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

        if response.is_directory_redirection:
            return False

        if request.method == "POST":
            return False

        return request.url == await self.persister.get_root_url()

    async def attack(self, request: Request, response: Optional[Response] = None):
        self.finished = True
        request_to_root = Request(request.url)
        modules_list = [ModuleCheckPoint, ModuleCitrix, ModuleForti, ModuleHarbor, ModuleUbika]
        for module in modules_list:
            mod = module(
                self.crawler, self.persister, self.options, Event(), self.crawler_configuration
            )
            await mod.attack(request_to_root)
