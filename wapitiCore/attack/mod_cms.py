#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2023-2024 Cyberwatch
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

from wapitiCore.attack.cms.mod_drupal_enum import ModuleDrupalEnum
from wapitiCore.attack.cms.mod_joomla_enum import ModuleJoomlaEnum
from wapitiCore.attack.cms.mod_prestashop_enum import ModulePrestashopEnum
from wapitiCore.attack.cms.mod_wp_enum import ModuleWpEnum
from wapitiCore.attack.cms.mod_spip_enum import ModuleSpipEnum


from wapitiCore.attack.attack import Attack
from wapitiCore.net import Request
from wapitiCore.net.response import Response

MSG_TECHNO_VERSIONED = "{0} {1} detected"


class ModuleCms(Attack):
    """Base class for detecting version."""
    name = "cms"

    versions = []

    async def must_attack(self, request: Request, response: Optional[Response] = None):
        if self.finished:
            return False

        if request.method == "POST":
            return False

        return request.url == await self.persister.get_root_url()

    async def attack(self, request: Request, response: Optional[Response] = None):
        self.finished = True
        request_to_root = Request(request.url)
        cms_list = self.cms.split(',')

        if "drupal" in cms_list:
            module = ModuleDrupalEnum(
                self.crawler, self.persister, self.options, Event(), self.crawler_configuration
            )
            await module.attack(request_to_root)
        if "joomla" in cms_list:
            module = ModuleJoomlaEnum(
                self.crawler, self.persister, self.options, Event(), self.crawler_configuration
            )
            await module.attack(request_to_root)
        if "prestashop" in cms_list:
            module = ModulePrestashopEnum(
                self.crawler, self.persister, self.options, Event(), self.crawler_configuration
            )
            await module.attack(request_to_root)
        if "spip" in cms_list:
            module = ModuleSpipEnum(
                self.crawler, self.persister, self.options, Event(), self.crawler_configuration
            )
            await module.attack(request_to_root)
        if "wp" in cms_list:
            module = ModuleWpEnum(
                self.crawler, self.persister, self.options, Event(), self.crawler_configuration
            )
            await module.attack(request_to_root)
