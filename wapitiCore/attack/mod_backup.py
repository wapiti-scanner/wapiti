#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (http://wapiti.sourceforge.io)
# Copyright (C) 2009-2020 Nicolas Surribas
#
# Original authors :
# Anthony DUBOCAGE
# Guillaume TRANCHANT
# Gregory FONTAINE
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
from os.path import splitext

from requests.exceptions import RequestException

from wapitiCore.attack.attack import Attack
from wapitiCore.language.vulnerability import Vulnerability, _
from wapitiCore.net import web


class mod_backup(Attack):
    """
    This class implements a "backup attack"
    """

    PAYLOADS_FILE = "backupPayloads.txt"

    name = "backup"

    do_get = False
    do_post = False

    def attack(self):
        http_resources = self.persister.get_links(attack_module=self.name) if self.do_get else []

        for original_request in http_resources:

            if original_request.file_name == "":
                yield original_request
                continue

            page = original_request.path
            headers = original_request.headers

            # Do not attack application-type files
            if "content-type" not in headers:
                # Sometimes there's no content-type... so we rely on the document extension
                if (page.split(".")[-1] not in self.allowed) and page[-1] != "/":
                    yield original_request
                    continue
            elif "text" not in headers["content-type"]:
                yield original_request
                continue

            for payload, flags in self.payloads:
                try:
                    payload = payload.replace("[FILE_NAME]", original_request.file_name)
                    payload = payload.replace("[FILE_NOEXT]", splitext(original_request.file_name)[0])
                    url = page.replace(original_request.file_name, payload)

                    if self.verbose == 2:
                        print("[¨] {0}".format(url))

                    if url not in self.attacked_get:
                        self.attacked_get.append(url)
                        evil_req = web.Request(url)

                        response = self.crawler.send(evil_req)
                        if response and response.status == 200:
                            self.log_red(_("Found backup file {}".format(evil_req.url)))

                            self.add_vuln(
                                request_id=original_request.path_id,
                                category=Vulnerability.BACKUP,
                                level=Vulnerability.HIGH_LEVEL,
                                request=evil_req,
                                info=_("Backup file {0} found for {1}").format(url, page)
                            )

                except (KeyboardInterrupt, RequestException) as exception:
                    yield exception

            yield original_request
