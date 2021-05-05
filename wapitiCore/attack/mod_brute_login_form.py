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
# This module can help to quickly find weak or default credentials in a web application.
# You should not rely on this module for performance or fine-tuned brute force attack.
# Using well-known tools like Hydra, Patator, Wfuzz or other tools supporting parallelism is recommended.
# This module may be handy for CTF though.
from os.path import join as path_join
from itertools import product

from httpx import RequestError

from wapitiCore.attack.attack import Attack
from wapitiCore.language.vulnerability import Messages, LOW_LEVEL, _
from wapitiCore.definitions.credentials import NAME
from wapitiCore.net.web import Request


class mod_brute_login_form(Attack):
    """Attempt to login on authentication forms using known weak credentials (like admin/admin)."""
    name = "brute_login_form"
    PAYLOADS_FILE = "passwords.txt"
    PAYLOADS_FILE_USER = "users.txt"
    PAYLOADS_SUCCESS = "successMessage.txt"
    PAYLOADS_FAIL = "incorrectMessage.txt"

    do_get = False
    do_post = False

    def check_success_auth(self, content_response: str):
        with open(path_join(self.DATA_DIR, self.PAYLOADS_SUCCESS), errors="ignore") as success_pattern_file:
            for success_pattern in success_pattern_file:
                if success_pattern.strip() in content_response:
                    return True

        return False

    def get_usernames(self):
        with open(path_join(self.DATA_DIR, self.PAYLOADS_FILE_USER), errors="ignore") as username_file:
            for line in username_file:
                username = line.strip()
                if username:
                    yield username

    def get_passwords(self):
        with open(path_join(self.DATA_DIR, self.PAYLOADS_FILE), errors="ignore") as password_file:
            for line in password_file:
                password = line.strip()
                if password:
                    yield password

    async def test_credentials(self, login_form, username_index, password_index, username, password):
        post_params = login_form.post_params
        get_params = login_form.get_params

        if login_form.method == "POST":
            post_params[username_index][1] = username
            post_params[password_index][1] = password
        else:
            get_params[username_index][1] = username
            get_params[password_index][1] = password

        login_request = Request(
            path=login_form.url,
            method=login_form.method,
            post_params=post_params,
            get_params=get_params,
            referer=login_form.referer,
            link_depth=login_form.link_depth
        )

        login_response = await self.crawler.async_send(
            login_request,
            follow_redirects=True
        )

        return login_response.content

    def must_attack(self, request: Request):
        # We leverage the fact that the crawler will fill password entries with a known placeholder
        if "Letm3in_" not in request.encoded_data + request.encoded_params:
            return False

        # We may want to remove this but if not available fallback to target URL
        if not request.referer:
            return False

        return True

    async def attack(self, request: Request):
        try:
            page = await self.crawler.async_get(Request(request.referer), follow_redirects=True)
        except RequestError:
            self.network_errors += 1
            return

        login_form, username_field_idx, password_field_idx = page.find_login_form()
        if not login_form:
            return

        try:
            failure_text = await self.test_credentials(
                login_form,
                username_field_idx, password_field_idx,
                "invalid", "invalid"
            )

            if self.check_success_auth(failure_text):
                # Ignore this case as it raises false positives
                return
        except RequestError:
            self.network_errors += 1
            return

        for username, password in product(self.get_usernames(), self.get_passwords()):
            if self._stop_event.is_set():
                break

            try:
                response = await self.test_credentials(
                    login_form,
                    username_field_idx, password_field_idx,
                    username, password
                )
            except RequestError:
                self.network_errors += 1
                continue

            if self.check_success_auth(response) and failure_text != response:
                vuln_message = _("Credentials found for URL {} : {} / {}").format(
                    request.referer,
                    username,
                    password
                )

                # Recreate the request that succeed in order to print and store it
                post_params = login_form.post_params
                get_params = login_form.get_params

                if login_form.method == "POST":
                    post_params[username_field_idx][1] = username
                    post_params[password_field_idx][1] = password
                else:
                    get_params[username_field_idx][1] = username
                    get_params[password_field_idx][1] = password

                evil_request = Request(
                    path=login_form.url,
                    method=login_form.method,
                    post_params=post_params,
                    get_params=get_params,
                    referer=login_form.referer,
                    link_depth=login_form.link_depth
                )

                self.add_vuln(
                    request_id=request.path_id,
                    category=NAME,
                    level=LOW_LEVEL,
                    request=evil_request,
                    info=vuln_message
                )

                self.log_red("---")
                self.log_red(vuln_message)
                self.log_red(Messages.MSG_EVIL_REQUEST)
                self.log_red(evil_request.http_repr())
                self.log_red("---")
                break
