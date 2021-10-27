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
import asyncio

from httpx import RequestError

from wapitiCore.attack.attack import Attack
from wapitiCore.language.vulnerability import Messages, _
from wapitiCore.definitions.credentials import NAME
from wapitiCore.net.web import Request
from wapitiCore.main.log import log_red


class ModuleBruteLoginForm(Attack):
    """Attempt to login on authentication forms using known weak credentials (like admin/admin)."""
    name = "brute_login_form"
    PAYLOADS_FILE = "passwords.txt"
    PAYLOADS_FILE_USER = "users.txt"
    PAYLOADS_SUCCESS = "successMessage.txt"
    PAYLOADS_FAIL = "incorrectMessage.txt"

    do_get = False
    do_post = False

    def check_success_auth(self, content_response: str):
        with open(
            path_join(self.DATA_DIR, self.PAYLOADS_SUCCESS),
            errors="ignore",
            encoding='utf-8'
        ) as success_pattern_file:
            for success_pattern in success_pattern_file:
                if success_pattern.strip() in content_response:
                    return True

        return False

    def get_usernames(self):
        with open(
            path_join(self.DATA_DIR, self.PAYLOADS_FILE_USER),
            errors="ignore",
            encoding='utf-8'
        ) as username_file:
            for line in username_file:
                username = line.strip()
                if username:
                    yield username

    def get_passwords(self):
        with open(
            path_join(self.DATA_DIR, self.PAYLOADS_FILE),
            errors="ignore",
            encoding='utf-8'
        ) as password_file:
            for line in password_file:
                password = line.strip()
                if password:
                    yield password

    async def send_credentials(self, login_form, username_index, password_index, username, password):
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

    async def must_attack(self, request: Request):
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
            failure_text = await self.send_credentials(
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

        tasks = set()
        pending_count = 0
        found = False

        creds_iterator = product(self.get_usernames(), self.get_passwords())
        while True:
            if pending_count < self.options["tasks"] and not self._stop_event.is_set() and not found:
                try:
                    username, password = next(creds_iterator)
                except StopIteration:
                    pass
                else:
                    task = asyncio.create_task(
                        self.test_credentials(
                            login_form,
                            username_field_idx,
                            password_field_idx,
                            username,
                            password,
                            failure_text
                        )
                    )
                    tasks.add(task)

            if not tasks:
                break

            done_tasks, pending_tasks = await asyncio.wait(
                tasks,
                timeout=0.01,
                return_when=asyncio.FIRST_COMPLETED
            )
            pending_count = len(pending_tasks)
            for task in done_tasks:
                try:
                    result = await task
                except RequestError:
                    self.network_errors += 1
                else:
                    if result:
                        found = True
                        username, password = result
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

                        await self.add_vuln_low(
                            request_id=request.path_id,
                            category=NAME,
                            request=evil_request,
                            info=vuln_message
                        )

                        log_red("---")
                        log_red(vuln_message)
                        log_red(Messages.MSG_EVIL_REQUEST)
                        log_red(evil_request.http_repr())
                        log_red("---")

                tasks.remove(task)

            if self._stop_event.is_set() or found:
                # If we found valid credentials we need to stop pending tasks as they may generate false positives
                # because the session is opened on the website and next attempts may appear as logged in
                for task in pending_tasks:
                    task.cancel()
                    tasks.remove(task)

    async def test_credentials(self, login_form, username_idx, password_idx, username, password, failure_text):
        response = await self.send_credentials(
                login_form,
                username_idx, password_idx,
                username, password
        )

        if self.check_success_auth(response) and failure_text != response:
            return username, password

        return None
