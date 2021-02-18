# This file is part of the Wapiti project (https://wapiti.sourceforge.io)
# Copyright (C) 2020-2021 Nicolas Surribas
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
from wapitiCore.attack.attack import Attack
from wapitiCore.net.web import Request
from wapitiCore.language.vulnerability import LOW_LEVEL, _
from wapitiCore.net.csp_utils import csp_header_to_dict, CSP_CHECK_LISTS, check_policy_values
from wapitiCore.definitions.csp import NAME

MSG_NO_CSP = _("CSP is not set")
MSG_CSP_MISSING = _("CSP attribute \"{0}\" is missing")
MSG_CSP_UNSAFE = _("CSP \"{0}\" value is not safe")


# This module check the basics recommendations of CSP
class mod_csp(Attack):
    """Evaluate the security level of Content Security Policies of the web server."""
    name = "csp"

    def attack(self):
        url = self.persister.get_root_url()
        request = Request(url)
        response = self.crawler.get(request, follow_redirects=True)

        if "Content-Security-Policy" not in response.headers:
            self.log_red(MSG_NO_CSP)
            self.add_vuln(
                category=NAME,
                level=LOW_LEVEL,
                request=request,
                info=MSG_NO_CSP
            )
        else:
            csp_dict = csp_header_to_dict(response.headers["Content-Security-Policy"])

            for policy_name in CSP_CHECK_LISTS:
                result = check_policy_values(policy_name, csp_dict)

                if result == -1:
                    self.log_red(MSG_CSP_MISSING.format(policy_name))
                    self.add_vuln(
                        category=NAME,
                        level=LOW_LEVEL,
                        request=request,
                        info=MSG_CSP_MISSING.format(policy_name)
                    )
                elif result == 0:
                    self.log_red(MSG_CSP_UNSAFE.format(policy_name))
                    self.add_vuln(
                        category=NAME,
                        level=LOW_LEVEL,
                        request=request,
                        info=MSG_CSP_UNSAFE.format(policy_name)
                    )

        yield
