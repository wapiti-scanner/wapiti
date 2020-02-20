#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (http://wapiti.sourceforge.io)
# Copyright (C) 2009-2020 Nicolas Surribas
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
import csv
import re
import os
import socket
import random

from requests.exceptions import RequestException

from wapitiCore.attack.attack import Attack
from wapitiCore.language.vulnerability import Vulnerability, _
from wapitiCore.net import web


# Nikto databases are csv files with the following fields (in order) :
#
#  1 - A unique identifier (number)
#  2 - The OSVDB reference number of the vulnerability
#  3 - Unknown (not used by Wapiti)
#  4 - The URL to check for. May contain a pattern to replace (eg: @CGIDIRS)
#  5 - The HTTP method to use when requesting the URL
#  6 - The HTTP status code returned when the vulnerability may exist
#      or a string the HTTP response may contain.
#  7 - Another condition for a possible vulnerability (6 OR 7)
#  8 - Another condition (must match for a possible vulnerability)
#  9 - A condition corresponding to an unexploitable webpage
# 10 - Another condition just like 9
# 11 - A description of the vulnerability with possible BID, CVE or MS references
# 12 - A url-form-encoded string (usually for POST requests)
#
# A possible vulnerability is reported in the following condition :
# ((6 or 7) and 8) and not (9 or 10)


class mod_nikto(Attack):
    """
    This class implements a Nikto attack
    """

    nikto_db = []

    name = "nikto"
    NIKTO_DB = "nikto_db"

    do_get = False
    do_post = False

    def __init__(self, crawler, persister, logger, attack_options):
        Attack.__init__(self, crawler, persister, logger, attack_options)
        user_config_dir = os.getenv("HOME") or os.getenv("USERPROFILE")
        user_config_dir += "/config"

        if not os.path.isdir(user_config_dir):
            os.makedirs(user_config_dir)
        try:
            with open(os.path.join(user_config_dir, self.NIKTO_DB)) as fd:
                reader = csv.reader(fd)
                self.nikto_db = [line for line in reader if line != [] and line[0].isdigit()]
        except IOError:
            try:
                print(_("Problem with local nikto database."))
                print(_("Downloading from the web..."))
                nikto_req = web.Request(
                    "https://raw.githubusercontent.com/sullo/nikto/master/program/databases/db_tests"
                )
                response = self.crawler.send(nikto_req)

                csv.register_dialect("nikto", quoting=csv.QUOTE_ALL, doublequote=False, escapechar="\\")
                reader = csv.reader(response.content.split("\n"), "nikto")
                self.nikto_db = [line for line in reader if line != [] and line[0].isdigit()]

                with open(os.path.join(user_config_dir, self.NIKTO_DB), "w") as fd:
                    writer = csv.writer(fd)
                    writer.writerows(self.nikto_db)

            except socket.timeout:
                print(_("Error downloading Nikto database"))

    def attack(self):
        junk_string = "w" + "".join([random.choice("0123456789abcdefghjijklmnopqrstuvwxyz") for __ in range(0, 5000)])
        urls = self.persister.get_links(attack_module=self.name) if self.do_get else []
        server = next(urls).hostname

        for line in self.nikto_db:
            match = match_or = match_and = False
            fail = fail_or = False

            osv_id = line[1]
            path = line[3]
            method = line[4]
            vuln_desc = line[10]
            post_data = line[11]

            path = path.replace("@CGIDIRS", "/cgi-bin/")
            path = path.replace("@ADMIN", "/admin/")
            path = path.replace("@NUKE", "/modules/")
            path = path.replace("@PHPMYADMIN", "/phpMyAdmin/")
            path = path.replace("@POSTNUKE", "/postnuke/")
            path = re.sub(r"JUNK\((\d+)\)", lambda x: junk_string[:int(x.group(1))], path)

            if path[0] == "@":
                continue
            if not path.startswith("/"):
                path = "/" + path

            try:
                url = "http://" + server + path
            except UnicodeDecodeError:
                continue

            if method == "GET":
                evil_request = web.Request(url)
            elif method == "POST":
                evil_request = web.Request(url, post_params=post_data, method=method)
            else:
                evil_request = web.Request(url, post_params=post_data, method=method)

            if self.verbose == 2:
                if method == "GET":
                    print("[¨] {0}".format(evil_request.url))
                else:
                    print("[¨] {0}".format(evil_request.http_repr()))

            try:
                response = self.crawler.send(evil_request)
            except RequestException as exception:
                # requests bug
                yield exception
                continue
            else:
                yield

            page = response.content
            code = response.status
            raw = " ".join([x + ": " + y for x, y in response.headers.items()])
            raw += page

            # First condition (match)
            if len(line[5]) == 3 and line[5].isdigit():
                if code == int(line[5]):
                    match = True
            else:
                if line[5] in raw:
                    match = True

            # Second condition (or)
            if line[6] != "":
                if len(line[6]) == 3 and line[6].isdigit():
                    if code == int(line[6]):
                        match_or = True
                else:
                    if line[6] in raw:
                        match_or = True

            # Third condition (and)
            if line[7] != "":
                if len(line[7]) == 3 and line[7].isdigit():
                    if code == int(line[7]):
                        match_and = True
                else:
                    if line[7] in raw:
                        match_and = True
            else:
                match_and = True

            # Fourth condition (fail)
            if line[8] != "":
                if len(line[8]) == 3 and line[8].isdigit():
                    if code == int(line[8]):
                        fail = True
                else:
                    if line[8] in raw:
                        fail = True

            # Fifth condition (or)
            if line[9] != "":
                if len(line[9]) == 3 and line[9].isdigit():
                    if code == int(line[9]):
                        fail_or = True
                else:
                    if line[9] in raw:
                        fail_or = True

            if ((match or match_or) and match_and) and not (fail or fail_or):
                self.log_red("---")
                self.log_red(vuln_desc)
                self.log_red(url)

                refs = []
                if osv_id != "0":
                    refs.append("http://osvdb.org/show/osvdb/" + osv_id)

                # CERT
                m = re.search("(CA-[0-9]{4}-[0-9]{2})", vuln_desc)
                if m is not None:
                    refs.append("http://www.cert.org/advisories/" + m.group(0) + ".html")

                # SecurityFocus
                m = re.search("BID-([0-9]{4})", vuln_desc)
                if m is not None:
                    refs.append("http://www.securityfocus.com/bid/" + m.group(1))

                # Mitre.org
                m = re.search("((CVE|CAN)-[0-9]{4}-[0-9]{4,})", vuln_desc)
                if m is not None:
                    refs.append("http://cve.mitre.org/cgi-bin/cvename.cgi?name=" + m.group(0))

                # CERT Incidents
                m = re.search("(IN-[0-9]{4}-[0-9]{2})", vuln_desc)
                if m is not None:
                    refs.append("http://www.cert.org/incident_notes/" + m.group(0) + ".html")

                # Microsoft Technet
                m = re.search("(MS[0-9]{2}-[0-9]{3})", vuln_desc)
                if m is not None:
                    refs.append("http://www.microsoft.com/technet/security/bulletin/" + m.group(0) + ".asp")

                info = vuln_desc
                if refs:
                    self.log_red(_("References:"))
                    self.log_red("  {0}".format("\n  ".join(refs)))

                    info += "\n" + _("References:") + "\n"
                    info += "\n".join(refs)

                self.log_red("---")

                self.add_vuln(
                    category=Vulnerability.NIKTO,
                    level=Vulnerability.HIGH_LEVEL,
                    request=evil_request,
                    info=info
                )
