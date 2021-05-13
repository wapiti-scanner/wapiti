#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti.sourceforge.io)
# Copyright (C) 2006-2021 Nicolas SURRIBAS
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
import sys
import argparse
import os
from urllib.parse import urlparse
from time import strftime, gmtime
from importlib import import_module
from operator import attrgetter
from itertools import chain
from traceback import print_tb
from collections import deque
from datetime import datetime
from uuid import uuid1
from sqlite3 import OperationalError
from hashlib import sha256
from random import choice
import codecs
from inspect import getdoc
import asyncio
import signal

import browser_cookie3
import httpx
from httpx import RequestError

from wapitiCore.language.language import _
from wapitiCore.language.logger import ConsoleLogger
from wapitiCore.definitions import anomalies, additionals, vulnerabilities, flatten_references

from wapitiCore.net import crawler, jsoncookie
from wapitiCore.net.web import Request
from wapitiCore.report import get_report_generator_instance, GENERATORS
from wapitiCore.net.sqlite_persister import SqlitePersister
from wapitiCore.moon import phase

from wapitiCore.attack import attack


BASE_DIR = None
WAPITI_VERSION = "Wapiti 3.0.5"
CONF_DIR = os.path.dirname(sys.modules["wapitiCore"].__file__)

SCAN_FORCE_VALUES = {
    "paranoid": 1,
    "sneaky": 0.7,
    "polite": 0.5,
    "normal": 0.2,
    "aggressive": 0.06,
    "insane": 0  # Special value that won't be really used
}


class InvalidOptionValue(Exception):
    def __init__(self, opt_name, opt_value):
        super().__init__()
        self.opt_name = opt_name
        self.opt_value = opt_value

    def __str__(self):
        return _("Invalid argument for option {0} : {1}").format(self.opt_name, self.opt_value)


stop_event = asyncio.Event()


def inner_ctrl_c_signal_handler():  # pylint: disable=unused-argument
    print(_("Waiting for running crawler tasks to finish, please wait."))
    stop_event.set()


def stop_attack_process():  # pylint: disable=unused-argument
    stop_event.set()


class Wapiti:
    """This class parse the options from the command line and set the modules and the HTTP engine accordingly.
    Launch wapiti without arguments or with the "-h" option for more information."""

    REPORT_DIR = "report"
    HOME_DIR = os.getenv("HOME") or os.getenv("USERPROFILE")
    COPY_REPORT_DIR = os.path.join(HOME_DIR, ".wapiti", "generated_report")

    def __init__(self, root_url, scope="folder", session_dir=None, config_dir=None):
        self.target_url = root_url
        self.server = urlparse(root_url).netloc

        self.crawler = crawler.AsyncCrawler(root_url)

        self.target_scope = scope
        if scope == "page":
            self.crawler.scope = crawler.Scope.PAGE
        elif scope == "folder":
            self.crawler.scope = crawler.Scope.FOLDER
        elif scope == "domain":
            self.crawler.scope = crawler.Scope.DOMAIN
        elif scope == "punk":
            self.crawler.scope = crawler.Scope.PUNK
        else:
            self.crawler.scope = crawler.Scope.URL

        self.report_gen = None
        self.report_generator_type = "html"
        self.output_file = ""

        self.urls = []
        self.forms = []
        self.attacks = []

        self.color = 0
        self.verbose = 0
        self.module_options = None
        self.attack_options = {}
        self._start_urls = deque([self.target_url])
        self._excluded_urls = []
        self._bad_params = set()
        self._max_depth = 40
        self._max_links_per_page = 0
        self._max_files_per_dir = 0
        self._scan_force = "normal"
        self._max_scan_time = 0
        self._max_attack_time = 0
        self._bug_report = True

        if session_dir:
            SqlitePersister.CRAWLER_DATA_DIR = session_dir

        if config_dir:
            SqlitePersister.CONFIG_DIR = config_dir

        self._history_file = os.path.join(
            SqlitePersister.CRAWLER_DATA_DIR,
            "{}_{}_{}.db".format(
                self.server.replace(':', '_'),
                self.target_scope,
                sha256(root_url.encode(errors="replace")).hexdigest()[:8]
            )
        )

        if not os.path.isdir(SqlitePersister.CRAWLER_DATA_DIR):
            os.makedirs(SqlitePersister.CRAWLER_DATA_DIR)

        self.persister = SqlitePersister(self._history_file)

    def _init_report(self):
        self.report_gen = get_report_generator_instance(self.report_generator_type.lower())

        self.report_gen.set_report_info(
            self.target_url,
            self.target_scope,
            gmtime(),
            WAPITI_VERSION
        )

        for vul in vulnerabilities:
            self.report_gen.add_vulnerability_type(
                vul.NAME,
                vul.DESCRIPTION,
                vul.SOLUTION,
                flatten_references(vul.REFERENCES)
            )

        for anomaly in anomalies:
            self.report_gen.add_anomaly_type(
                anomaly.NAME,
                anomaly.DESCRIPTION,
                anomaly.SOLUTION,
                flatten_references(anomaly.REFERENCES)
            )

        for additional in additionals:
            self.report_gen.add_additional_type(
                additional.NAME,
                additional.DESCRIPTION,
                additional.SOLUTION,
                flatten_references(additional.REFERENCES)
            )

    def _init_attacks(self, stop_event):
        self._init_report()

        logger = ConsoleLogger()
        if self.color:
            logger.color = True

        print(_("[*] Loading modules:"))
        modules_list = sorted(module_name[4:] for module_name in attack.modules)
        print("\t {0}".format(", ".join(modules_list)))
        for mod_name in attack.modules:
            try:
                mod = import_module("wapitiCore.attack." + mod_name)
            except ImportError:
                print(_("[!] Could not find module {0}").format(mod_name))
                continue

            mod_instance = getattr(mod, mod_name)(self.crawler, self.persister, logger, self.attack_options, stop_event)
            if hasattr(mod_instance, "set_timeout"):
                mod_instance.set_timeout(self.crawler.timeout)
            self.attacks.append(mod_instance)

            self.attacks.sort(key=attrgetter("PRIORITY"))

        for attack_module in self.attacks:
            attack_module.set_verbose(self.verbose)
            if attack_module.name not in attack.commons:
                attack_module.do_get = False
                attack_module.do_post = False

            if self.color == 1:
                attack_module.set_color()

        # Custom list of modules was specified
        if self.module_options is not None:
            # First deactivate all modules
            for attack_module in self.attacks:
                attack_module.do_get = False
                attack_module.do_post = False

            opts = self.module_options.split(",")

            for module_opt in opts:
                if module_opt.strip() == "":
                    continue

                method = ""
                if module_opt.find(":") > 0:
                    module_name, method = module_opt.split(":", 1)
                else:
                    module_name = module_opt

                # deactivate some module options
                if module_name.startswith("-"):
                    module_name = module_name[1:]
                    if module_name in ("all", "common"):
                        for attack_module in self.attacks:
                            if module_name == "all" or attack_module.name in attack.commons:
                                if not method:
                                    attack_module.do_get = attack_module.do_post = False
                                elif method == "get":
                                    attack_module.do_get = False
                                elif method == "post":
                                    attack_module.do_post = False
                    else:
                        found = False
                        for attack_module in self.attacks:
                            if attack_module.name == module_name:
                                found = True
                                if not method:
                                    attack_module.do_get = attack_module.do_post = False
                                elif method == "get":
                                    attack_module.do_get = False
                                elif method == "post":
                                    attack_module.do_post = False
                        if not found:
                            print(_("[!] Unable to find a module named {0}").format(module_name))

                # activate some module options
                else:
                    if module_name.startswith("+"):
                        module_name = module_name[1:]

                    if module_name in ("all", "common"):
                        for attack_module in self.attacks:
                            if module_name == "all" or attack_module.name in attack.commons:
                                if not method:
                                    attack_module.do_get = attack_module.do_post = True
                                elif method == "get":
                                    attack_module.do_get = True
                                elif method == "post":
                                    attack_module.do_post = True
                    else:
                        found = False
                        for attack_module in self.attacks:
                            if attack_module.name == module_name:
                                found = True
                                if not method:
                                    attack_module.do_get = attack_module.do_post = True
                                elif method == "get":
                                    attack_module.do_get = True
                                elif method == "post":
                                    attack_module.do_post = True
                        if not found:
                            print(_("[!] Unable to find a module named {0}").format(module_name))

    async def update(self):
        """Update modules that implement an update method"""
        logger = ConsoleLogger()
        if self.color:
            logger.color = True

        stop_event = asyncio.Event()
        for mod_name in attack.modules:
            mod = import_module("wapitiCore.attack." + mod_name)
            mod_instance = getattr(mod, mod_name)(self.crawler, self.persister, logger, self.attack_options, stop_event)
            if hasattr(mod_instance, "update"):
                print(_("Updating module {0}").format(mod_name[4:]))
                await mod_instance.update()
        print(_("Update done."))

    def load_scan_state(self):
        for resource in self.persister.get_to_browse():
            self._start_urls.append(resource)
        for resource in self.persister.get_links():
            self._excluded_urls.append(resource)
        for resource in self.persister.get_forms():
            self._excluded_urls.append(resource)

        self.persister.set_root_url(self.target_url)

    def save_scan_state(self):
        print(_("[*] Saving scan state, please wait..."))
        # Not yet scanned URLs are all saved in one single time (bulk insert + final commit)
        self.persister.set_to_browse(self._start_urls)

        print('')
        print(_(" Note"))
        print("========")

        print(_("This scan has been saved in the file {0}").format(self.persister.output_file))
        # if stopped and self._start_urls:
        #     print(_("The scan will be resumed next time unless you pass the --skip-crawl option."))

    async def browse(self, stop_event: asyncio.Event, parallelism: int = 8):
        """Extract hyperlinks and forms from the webpages found on the website"""
        explorer = crawler.Explorer(self.crawler, stop_event, parallelism=parallelism)
        explorer.max_depth = self._max_depth
        explorer.max_files_per_dir = self._max_files_per_dir
        explorer.max_requests_per_depth = self._max_links_per_page
        explorer.forbidden_parameters = self._bad_params
        explorer.qs_limit = SCAN_FORCE_VALUES[self._scan_force]
        explorer.verbose = (self.verbose > 0)
        explorer.load_saved_state(self.persister.output_file[:-2] + "pkl")

        start = datetime.utcnow()

        async for resource in explorer.async_explore(self._start_urls, self._excluded_urls):
            # Browsed URLs are saved one at a time
            self.persister.add_request(resource)
            if not stop_event.is_set() and (datetime.utcnow() - start).total_seconds() > self._max_scan_time >= 1:
                print(_("Max scan time was reached, stopping."))
                stop_event.set()

        # Let's save explorer values (limits)
        explorer.save_state(self.persister.output_file[:-2] + "pkl")

    async def attack(self, stop_event: asyncio.Event):
        """Launch the attacks based on the preferences set by the command line"""
        self._init_attacks(stop_event)
        answer = "0"

        for attack_module in self.attacks:
            if stop_event.is_set():
                break

            start = datetime.utcnow()
            if attack_module.do_get is False and attack_module.do_post is False:
                continue

            print('')
            if attack_module.require:
                attack_name_list = [attack.name for attack in self.attacks if attack.name in attack_module.require and
                                    (attack.do_get or attack.do_post)]
                if attack_module.require != attack_name_list:
                    print(_("[!] Missing dependencies for module {0}:").format(attack_module.name))
                    print("  {0}".format(",".join([attack for attack in attack_module.require
                                                   if attack not in attack_name_list])))
                    continue

                attack_module.load_require(
                    [attack for attack in self.attacks if attack.name in attack_module.require]
                )

            attack_module.log_green(_("[*] Launching module {0}"), attack_module.name)

            already_attacked = self.persister.count_attacked(attack_module.name)
            if already_attacked:
                attack_module.log_green(
                    _("[*] {0} pages were previously attacked and will be skipped"),
                    already_attacked
                )

            resources_to_attack = []
            if attack_module.do_get:
                resources_to_attack.append(self.persister.get_links(attack_module=attack_module.name))
            if attack_module.do_post:
                resources_to_attack.append(self.persister.get_forms(attack_module=attack_module.name))

            generator = chain.from_iterable(resources_to_attack)

            answer = "0"
            while True:
                if stop_event.is_set():
                    print('')
                    print(_("Attack process was interrupted. Do you want to:"))
                    print(_("\tr) stop everything here and generate the (R)eport"))
                    print(_("\tn) move to the (N)ext attack module (if any)"))
                    print(_("\tq) (Q)uit without generating the report"))
                    print(_("\tc) (C)ontinue the current attack"))

                    while True:
                        try:
                            answer = input("? ").strip().lower()
                        except UnicodeDecodeError:
                            pass

                        if answer not in ("r", "n", "q", "c"):
                            print(_("Invalid choice. Valid choices are r, n, q and c."))
                        else:
                            break

                    if answer in ("n", "c"):
                        stop_event.clear()

                    if answer in ("r", "n", "q"):
                        break

                    if answer == "c":
                        continue

                try:
                    original_request = next(generator)
                    if attack_module.must_attack(original_request):
                        if self.verbose >= 1:
                            print("[+] {}".format(original_request))

                        await attack_module.attack(original_request)

                    if (datetime.utcnow() - start).total_seconds() > self._max_attack_time >= 1:
                        print(_("Max attack time was reached for module {0}, stopping.".format(attack_module.name)))
                        break
                except RequestError:
                    # Hmmm it should be caught inside the module
                    await asyncio.sleep(1)
                    continue
                except StopIteration:
                    break
                except Exception as exception:
                    # Catch every possible exceptions and print it
                    exception_traceback = sys.exc_info()[2]
                    print(exception.__class__.__name__, exception)
                    print_tb(exception_traceback)

                    if self._bug_report:
                        traceback_file = str(uuid1())
                        with open(traceback_file, "w") as traceback_fd:
                            print_tb(exception_traceback, file=traceback_fd)
                            print("{}: {}".format(exception.__class__.__name__, exception), file=traceback_fd)
                            print("Occurred in {} on {}".format(attack_module.name, self.target_url), file=traceback_fd)
                            print("{}. httpx {}. OS {}".format(WAPITI_VERSION, httpx.__version__, sys.platform))

                        try:
                            upload_request = Request(
                                "https://wapiti3.ovh/upload.php",
                                file_params=[
                                    ["crash_report", (traceback_file, open(traceback_file, "rb").read(), "text/plain")]
                                ]
                            )
                            page = await self.crawler.async_send(upload_request)
                            print(_("Sending crash report {} ... {}").format(traceback_file, page.content))
                        except RequestError:
                            print(_("Error sending crash report"))
                        os.unlink(traceback_file)
                else:
                    if original_request.path_id is not None:
                        self.persister.set_attacked(original_request.path_id, attack_module.name)

            if hasattr(attack_module, "finish"):
                await attack_module.finish()

            if attack_module.network_errors:
                print(_("{} requests were skipped due to network issues").format(attack_module.network_errors))

            if answer == "1":
                break

        if answer == "q":
            await self.crawler.close()
            return

        # if self.crawler.get_uploads():
        #     print('')
        #     print(_("Upload scripts found:"))
        #     print("----------------------")
        #     for upload_form in self.crawler.get_uploads():
        #         print(upload_form)
        if not self.output_file:
            if self.report_generator_type == "html":
                self.output_file = self.COPY_REPORT_DIR
            else:
                filename = "{}_{}".format(
                    self.server.replace(":", "_"),
                    strftime("%m%d%Y_%H%M", self.report_gen.scan_date)
                )
                self.output_file = filename + "." + self.report_generator_type

        for payload in self.persister.get_payloads():
            if payload.type == "vulnerability":
                self.report_gen.add_vulnerability(
                    category=payload.category,
                    level=payload.level,
                    request=payload.evil_request,
                    parameter=payload.parameter,
                    info=payload.info
                )
            elif payload.type == "anomaly":
                self.report_gen.add_anomaly(
                    category=payload.category,
                    level=payload.level,
                    request=payload.evil_request,
                    parameter=payload.parameter,
                    info=payload.info
                )
            elif payload.type == "additional":
                self.report_gen.add_additional(
                    category=payload.category,
                    level=payload.level,
                    request=payload.evil_request,
                    parameter=payload.parameter,
                    info=payload.info
                )

        self.report_gen.generate_report(self.output_file)
        print('')
        print(_("Report"))
        print("------")
        print(_("A report has been generated in the file {0}").format(self.output_file))
        if self.report_generator_type == "html":
            print(_("Open {0} with a browser to see this report.").format(self.report_gen.final_path))

        await self.crawler.close()

    def set_timeout(self, timeout: float = 6.0):
        """Set the timeout for the time waiting for a HTTP response"""
        self.crawler.timeout = timeout

    def set_verify_ssl(self, verify: bool = False):
        """Set whether SSL must be verified."""
        self.crawler.secure = verify

    def set_proxy(self, proxy: str):
        """Set a proxy to use for HTTP requests."""
        self.crawler.set_proxy(proxy)

    def add_start_url(self, url: str):
        """Specify an URL to start the scan with. Can be called several times."""
        self._start_urls.append(url)

    def add_excluded_url(self, url_or_pattern: str):
        """Specify an URL to exclude from the scan. Can be called several times."""
        self._excluded_urls.append(url_or_pattern)

    def set_cookie_file(self, cookie: str):
        """Load session cookies from a cookie file"""
        if os.path.isfile(cookie):
            json_cookie = jsoncookie.JsonCookie()
            json_cookie.open(cookie)
            cookiejar = json_cookie.cookiejar(self.server)
            json_cookie.close()
            self.crawler.session_cookies = cookiejar

    def load_browser_cookies(self, browser_name: str):
        """Load session cookies from a browser"""
        browser_name = browser_name.lower()
        if browser_name == "firefox":
            cookiejar = browser_cookie3.firefox()
            self.crawler.session_cookies = cookiejar
        elif browser_name == "chrome":
            cookiejar = browser_cookie3.chrome()
            # There is a bug with version 0.11.4 of browser_cookie3 and we have to overwrite expiration date
            # Upgrading to latest version gave more errors so let's keep an eye on future releases
            for cookie in cookiejar:
                cookie.expires = None
            self.crawler.session_cookies = cookiejar
        else:
            raise InvalidOptionValue('--cookie', browser_name)

    def set_drop_cookies(self):
        self.crawler.drop_cookies = True

    def set_auth_credentials(self, auth_basic: tuple):
        """Set credentials to use if the website require an authentication."""
        self.crawler.credentials = auth_basic

    def set_auth_type(self, auth_method: str):
        """Set the authentication method to use."""
        self.crawler.auth_method = auth_method

    def add_bad_param(self, param_name: str):
        """Exclude a parameter from an url (urls with this parameter will be
        modified. This function can be call several times"""
        self._bad_params.add(param_name)

    def set_max_depth(self, limit: int):
        """Set how deep the scanner should explore the website"""
        self._max_depth = limit

    def set_max_links_per_page(self, limit: int):
        self._max_links_per_page = limit

    def set_max_files_per_dir(self, limit: int):
        self._max_files_per_dir = limit

    def set_scan_force(self, force: str):
        self._scan_force = force

    def set_max_scan_time(self, seconds: float):
        self._max_scan_time = seconds

    def set_max_attack_time(self, seconds: float):
        self._max_attack_time = seconds

    def set_color(self):
        """Put colors in the console output (terminal must support colors)"""
        self.color = 1

    def verbosity(self, verbose: int):
        """Define the level of verbosity of the output."""
        self.verbose = verbose

    def set_bug_reporting(self, value: bool):
        self._bug_report = value

    def set_attack_options(self, options: dict = None):
        self.attack_options = options if isinstance(options, dict) else {}

    def set_modules(self, options=""):
        """Activate or deactivate (default) all attacks"""
        self.module_options = options

    def set_report_generator_type(self, report_type="xml"):
        """Set the format of the generated report. Can be html, json, txt or xml"""
        self.report_generator_type = report_type

    def set_output_file(self, output_file: str):
        """Set the filename where the report will be written"""
        self.output_file = output_file

    def add_custom_header(self, key: str, value: str):
        self.crawler.add_custom_header(key, value)

    def flush_attacks(self):
        self.persister.flush_attacks()

    def flush_session(self):
        self.persister.close()
        try:
            os.unlink(self._history_file)
        except FileNotFoundError:
            pass

        try:
            os.unlink(self.persister.output_file[:-2] + "pkl")
        except FileNotFoundError:
            pass
        self.persister = SqlitePersister(self._history_file)

    def count_resources(self) -> int:
        return self.persister.count_paths()

    def has_scan_started(self) -> bool:
        return self.persister.has_scan_started()

    def have_attacks_started(self) -> bool:
        return self.persister.have_attacks_started()


def fix_url_path(url):
    """Fix the url path if its not defined"""
    return url if urlparse(url).path else url + '/'


def is_valid_endpoint(url_type, url):
    """Verify if the url provided has the right format"""
    try:
        parts = urlparse(url)
    except ValueError:
        print('ValueError')
        return False
    else:
        if parts.params or parts.query or parts.fragment:
            print(_("Error: {} must not contain params, query or fragment!").format(url_type))
            return False
        if parts.scheme in ("http", "https") and parts.netloc:
            return True
    print(_("Error: {} must contain scheme and host").format(url_type))
    return False


def ping(url):
    try:
        httpx.get(url, timeout=5)
    except RequestError:
        return False
    return True


async def wapiti_main():
    banners = [
        """
     __      __               .__  __  .__________
    /  \\    /  \\_____  ______ |__|/  |_|__\\_____  \\
    \\   \\/\\/   /\\__  \\ \\____ \\|  \\   __\\  | _(__  <
     \\        /  / __ \\|  |_> >  ||  | |  |/       \\
      \\__/\\  /  (____  /   __/|__||__| |__/______  /
           \\/        \\/|__|                      \\/""",
        """
     __    __            _ _   _ _____
    / / /\\ \\ \\__ _ _ __ (_) |_(_)___ /
    \\ \\/  \\/ / _` | '_ \\| | __| | |_ \\
     \\  /\\  / (_| | |_) | | |_| |___) |
      \\/  \\/ \\__,_| .__/|_|\\__|_|____/
                  |_|                 """,
        """
 ██╗    ██╗ █████╗ ██████╗ ██╗████████╗██╗██████╗
 ██║    ██║██╔══██╗██╔══██╗██║╚══██╔══╝██║╚════██╗
 ██║ █╗ ██║███████║██████╔╝██║   ██║   ██║ █████╔╝
 ██║███╗██║██╔══██║██╔═══╝ ██║   ██║   ██║ ╚═══██╗
 ╚███╔███╔╝██║  ██║██║     ██║   ██║   ██║██████╔╝
  ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝     ╚═╝   ╚═╝   ╚═╝╚═════╝  """
    ]

    print(choice(banners))
    print("Wapiti-3.0.5 (wapiti.sourceforge.io)")
    moon_phase = phase()
    if moon_phase == "full":
        print(_("[*] You are lucky! Full moon tonight."))
    elif moon_phase == "new":
        print(_("[*] Be careful! New moon tonight."))

    if datetime.now().weekday() == 4:
        if datetime.now().day == 13:
            print(_("[*] Watch out! Bad things can happen on Friday the 13th."))
        elif datetime.now().month == 8 and datetime.now().day < 8:
            print(_("[*] Today is International Beer Day!"))

    if datetime.now().month == 5 and datetime.now().day == 4:
        print(_("[*] May the force be with you!"))
    elif datetime.now().month == datetime.now().day == 1:
        print(_("[*] Happy new year!"))
    elif datetime.now().month == 12 and datetime.now().day == 25:
        print(_("[*] Merry christmas!"))
    elif datetime.now().month == 3 and datetime.now().day == 31:
        print(_("[*] Today is world backup day! Is your data safe?"))

    parser = argparse.ArgumentParser(description="Wapiti-3.0.5: Web application vulnerability scanner")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-u", "--url",
        help=_("The base URL used to define the scan scope (default scope is folder)"),
        metavar="URL", dest="base_url",
        default="http://example.com/"
        # required=True
    )

    parser.add_argument(
        "--scope",
        help=_("Set scan scope"),
        default="folder",
        choices=["page", "folder", "domain", "url", "punk"]
    )

    parser.add_argument(
        "-m", "--module",
        dest="modules", default=None,
        help=_("List of modules to load"),
        metavar="MODULES_LIST"
    )

    group.add_argument(
        "--list-modules",
        action="store_true",
        help=_("List Wapiti attack modules and exit")
    )

    group.add_argument(
        "--update",
        action="store_true",
        help=_("Update Wapiti attack modules and exit")
    )

    parser.add_argument(
        "-l", "--level",
        metavar="LEVEL",
        dest="level",
        help=_("Set attack level"),
        default=1,
        type=int,
        choices=[1, 2]
    )

    parser.add_argument(
        "-p", "--proxy",
        default=argparse.SUPPRESS,
        help=_("Set the HTTP(S) proxy to use. Supported: http(s) and socks proxies"),
        metavar="PROXY_URL",
        dest="proxy"
    )

    parser.add_argument(
        "--tor",
        action="store_true",
        help=_("Use Tor listener (127.0.0.1:9050)")
    )

    parser.add_argument(
        "-a", "--auth-cred",
        dest="credentials",
        default=argparse.SUPPRESS,
        help=_("Set HTTP authentication credentials"),
        metavar="CREDENTIALS"
    )

    parser.add_argument(
        "--auth-type",
        default=argparse.SUPPRESS,
        help=_("Set the authentication type to use"),
        choices=["basic", "digest", "ntlm", "post"]
    )

    parser.add_argument(
        "-c", "--cookie",
        help=_("Set a JSON cookie file to use.") + " " + _(
            "You can also pass 'firefox' or 'chrome' to load cookies from your browser."
        ),
        default=argparse.SUPPRESS,
        metavar="COOKIE_FILE"
    )

    parser.add_argument(
        "--drop-set-cookie",
        action="store_true",
        help=_("Ignore Set-Cookie header from HTTP responses")
    )

    parser.add_argument(
        "--skip-crawl",
        action="store_true",
        help=_("Don't resume the scanning process, attack URLs scanned during a previous session")
    )

    parser.add_argument(
        "--resume-crawl",
        action="store_true",
        help=_("Resume the scanning process (if stopped) even if some attacks were previously performed")
    )

    parser.add_argument(
        "--flush-attacks",
        action="store_true",
        help=_("Flush attack history and vulnerabilities for the current session")
    )

    parser.add_argument(
        "--flush-session",
        action="store_true",
        help=_("Flush everything that was previously found for this target (crawled URLs, vulns, etc)")
    )

    parser.add_argument(
        "--store-session",
        help=_("Directory where to store attack history and session data."),
        default=None,
        metavar="PATH",
    )

    parser.add_argument(
        "--store-config",
        help=_("Directory where to store configuration databases."),
        default=None,
        metavar="PATH",
    )

    parser.add_argument(
        "-s", "--start",
        action="append",
        default=[],
        help=_("Adds an url to start scan with"),
        metavar="URL",
        dest="starting_urls"
    )

    parser.add_argument(
        "-x", "--exclude",
        action="append",
        default=[],
        help=_("Adds an url to exclude from the scan"),
        metavar="URL",
        dest="excluded_urls"
    )

    parser.add_argument(
        "-r", "--remove",
        action="append",
        default=[],
        help=_("Remove this parameter from urls"),
        metavar="PARAMETER",
        dest="excluded_parameters"
    )

    parser.add_argument(
        "--skip",
        action="append",
        default=[],
        help=_("Skip attacking given parameter(s)"),
        metavar="PARAMETER",
        dest="skipped_parameters"
    )

    parser.add_argument(
        "-d", "--depth",
        help=_("Set how deep the scanner should explore the website"),
        type=int, default=40
    )

    parser.add_argument(
        "--max-links-per-page",
        metavar="MAX",
        help=_("Set how many (in-scope) links the scanner should extract for each page"),
        type=int, default=100
    )

    parser.add_argument(
        "--max-files-per-dir",
        metavar="MAX",
        help=_("Set how many pages the scanner should explore per directory"),
        type=int, default=0
    )

    parser.add_argument(
        "--max-scan-time",
        metavar="SECONDS",
        help=_("Set how many seconds you want the scan to last (floats accepted)"),
        type=float, default=0
    )

    parser.add_argument(
        "--max-attack-time",
        metavar="SECONDS",
        help=_("Set how many seconds you want each attack module to last (floats accepted)"),
        type=float, default=0
    )

    parser.add_argument(
        "--max-parameters",
        metavar="MAX",
        help=_("URLs and forms having more than MAX input parameters will be erased before attack."),
        type=int, default=0
    )

    parser.add_argument(
        "-S", "--scan-force",
        metavar="FORCE",
        help=_(
            "Easy way to reduce the number of scanned and attacked URLs.\n"
            "Possible values: paranoid, sneaky, polite, normal, aggressive, insane"
        ),
        choices=["paranoid", "sneaky", "polite", "normal", "aggressive", "insane"],
        default="normal"
    )

    parser.add_argument(
        "--tasks",
        metavar="tasks",
        help=_("Number of concurrent tasks to use for the exploration (crawling) of the target."),
        type=int, default=8
    )

    parser.add_argument(
        "-t", "--timeout",
        type=float, default=6.0,
        help=_("Set timeout for requests"),
        metavar="SECONDS"
    )

    parser.add_argument(
        "-H", "--header",
        action="append",
        default=[],
        help=_("Set a custom header to use for every requests"),
        metavar="HEADER",
        dest="headers"
    )

    parser.add_argument(
        "-A", "--user-agent",
        default=argparse.SUPPRESS,
        help=_("Set a custom user-agent to use for every requests"),
        metavar="AGENT",
        dest="user_agent"
    )

    parser.add_argument(
        "--verify-ssl",
        default=0,
        dest="check_ssl",
        help=_("Set SSL check (default is no check)"),
        type=int,
        choices=[0, 1]
    )

    parser.add_argument(
        "--color",
        action="store_true",
        help=_("Colorize output")
    )

    parser.add_argument(
        "-v", "--verbose",
        metavar="LEVEL",
        dest="verbosity",
        help=_("Set verbosity level (0: quiet, 1: normal, 2: verbose)"),
        default=0,
        type=int,
        choices=range(0, 3)
    )

    parser.add_argument(
        "-f", "--format",
        metavar="FORMAT",
        help=_("Set output format. Supported:") + " " + ", ".join(sorted(GENERATORS)) + ". " + _("Default is html."),
        default="html",
        choices=GENERATORS.keys()
    )

    parser.add_argument(
        "-o", "--output",
        metavar="OUTPUT_PATH",
        default=argparse.SUPPRESS,
        help=_("Output file or folder")
    )

    parser.add_argument(
        "--external-endpoint",
        metavar="EXTERNAL_ENDPOINT_URL",
        default=argparse.SUPPRESS,
        help=_("Url serving as endpoint for target")
    )

    parser.add_argument(
        "--internal-endpoint",
        metavar="INTERNAL_ENDPOINT_URL",
        default=argparse.SUPPRESS,
        help=_("Url serving as endpoint for attacker")
    )

    parser.add_argument(
        "--endpoint",
        metavar="ENDPOINT_URL",
        default="https://wapiti3.ovh/",
        help=_("Url serving as endpoint for both attacker and target")
    )

    parser.add_argument(
        "--no-bugreport",
        action="store_true",
        help=_("Don't send automatic bug report when an attack module fails")
    )

    parser.add_argument(
        "--version",
        action="version",
        help=_("Show program's version number and exit"),
        version=WAPITI_VERSION
    )

    args = parser.parse_args()

    if args.tasks < 1:
        print(_("Number of concurrent tasks must be 1 or above!"))
        sys.exit(2)

    if args.scope == "punk":
        print(_("[*] Do you feel lucky punk?"))

    if args.list_modules:
        print(_("[*] Available modules:"))
        modules_list = sorted(module_name[4:] for module_name in attack.modules)
        for module_name in modules_list:
            mod = import_module("wapitiCore.attack.mod_" + module_name)
            is_common = " (used by default)" if module_name in attack.commons else ""
            print("\t{}{}".format(module_name, is_common))
            print("\t\t" + getdoc(getattr(mod, "mod_" + module_name)))
            print('')
        sys.exit()

    url = fix_url_path(args.base_url)

    parts = urlparse(url)
    if not parts.scheme or not parts.netloc:
        print(_("Invalid base URL was specified, please give a complete URL with protocol scheme."))
        sys.exit()

    wap = Wapiti(url, scope=args.scope, session_dir=args.store_session, config_dir=args.store_config)

    if args.update:
        print(_("[*] Updating modules"))
        attack_options = {"level": args.level, "timeout": args.timeout}
        wap.set_attack_options(attack_options)
        await wap.update()
        await wap.crawler.close()
        sys.exit()

    try:
        for start_url in args.starting_urls:
            if start_url.startswith(("http://", "https://")):
                wap.add_start_url(start_url)
            elif os.path.isfile(start_url):
                try:
                    urlfd = codecs.open(start_url, encoding="UTF-8")
                    for urlline in urlfd:
                        urlline = urlline.strip()
                        if urlline.startswith(("http://", "https://")):
                            wap.add_start_url(urlline)
                    urlfd.close()
                except UnicodeDecodeError:
                    print(_("Error: File given with the -s option must be UTF-8 encoded !"))
                    raise InvalidOptionValue("-s", start_url)
            else:
                raise InvalidOptionValue('-s', start_url)

        for exclude_url in args.excluded_urls:
            if exclude_url.startswith(("http://", "https://")):
                wap.add_excluded_url(exclude_url)
            else:
                raise InvalidOptionValue("-x", exclude_url)

        if "proxy" in args:
            wap.set_proxy(args.proxy)

        if args.tor:
            wap.set_proxy("socks://127.0.0.1:9050/")

        if "cookie" in args:
            if os.path.isfile(args.cookie):
                wap.set_cookie_file(args.cookie)
            elif args.cookie.lower() in ("chrome", "firefox"):
                wap.load_browser_cookies(args.cookie)
            else:
                raise InvalidOptionValue("-c", args.cookie)

        if args.drop_set_cookie:
            wap.set_drop_cookies()

        if "credentials" in args:
            if "%" in args.credentials:
                wap.set_auth_credentials(args.credentials.split("%", 1))
            else:
                raise InvalidOptionValue("-a", args.credentials)

        if "auth_type" in args:
            if args.auth_type == "post" and args.starting_urls != []:
                wap.crawler.auth_url = args.starting_urls[0]
            else:
                wap.set_auth_type(args.auth_type)

        for bad_param in args.excluded_parameters:
            wap.add_bad_param(bad_param)

        wap.set_max_depth(args.depth)
        wap.set_max_files_per_dir(args.max_files_per_dir)
        wap.set_max_links_per_page(args.max_links_per_page)
        wap.set_scan_force(args.scan_force)
        wap.set_max_scan_time(args.max_scan_time)
        wap.set_max_attack_time(args.max_attack_time)

        # should be a setter
        wap.verbosity(args.verbosity)
        if args.color:
            wap.set_color()
        wap.set_timeout(args.timeout)
        wap.set_modules(args.modules)

        if args.no_bugreport:
            wap.set_bug_reporting(False)

        if "user_agent" in args:
            wap.add_custom_header("user-agent", args.user_agent)

        for custom_header in args.headers:
            if ":" in custom_header:
                hdr_name, hdr_value = custom_header.split(":", 1)
                wap.add_custom_header(hdr_name.strip(), hdr_value.strip())

        if "output" in args:
            wap.set_output_file(args.output)

        if args.format not in GENERATORS:
            raise InvalidOptionValue("-f", args.format)

        wap.set_report_generator_type(args.format)

        wap.set_verify_ssl(bool(args.check_ssl))

        attack_options = {
            "level": args.level,
            "timeout": args.timeout
        }

        if "endpoint" in args:
            endpoint = fix_url_path(args.endpoint)
            if is_valid_endpoint('ENDPOINT', endpoint):
                attack_options["external_endpoint"] = endpoint
                attack_options["internal_endpoint"] = endpoint
            else:
                raise InvalidOptionValue("--endpoint", args.endpoint)

        if "external_endpoint" in args:
            external_endpoint = fix_url_path(args.external_endpoint)
            if is_valid_endpoint('EXTERNAL ENDPOINT', external_endpoint):
                attack_options["external_endpoint"] = external_endpoint
            else:
                raise InvalidOptionValue("--external-endpoint", external_endpoint)

        if "internal_endpoint" in args:
            internal_endpoint = fix_url_path(args.internal_endpoint)
            if is_valid_endpoint('INTERNAL ENDPOINT', internal_endpoint):
                if ping(internal_endpoint):
                    attack_options["internal_endpoint"] = internal_endpoint
                else:
                    print(_("Error: Internal endpoint URL must be accessible from Wapiti!"))
                    raise InvalidOptionValue("--internal-endpoint", internal_endpoint)
            else:
                raise InvalidOptionValue("--internal-endpoint", internal_endpoint)

        if args.skipped_parameters:
            attack_options["skipped_parameters"] = set(args.skipped_parameters)

        wap.set_attack_options(attack_options)

        if args.flush_attacks:
            wap.flush_attacks()

        if args.flush_session:
            wap.flush_session()

    except InvalidOptionValue as msg:
        print(msg)
        sys.exit(2)

    loop = asyncio.get_event_loop()

    try:
        if not args.skip_crawl:
            if wap.have_attacks_started() and not args.resume_crawl:
                pass
            else:
                if wap.has_scan_started():
                    print(_("[*] Resuming scan from previous session, please wait"))

                if "auth_type" in args and args.auth_type == "post":
                    await wap.crawler.async_try_login(wap.crawler.auth_url)

                wap.load_scan_state()
                loop.add_signal_handler(signal.SIGINT, inner_ctrl_c_signal_handler)
                await wap.browse(stop_event, parallelism=args.tasks)
                loop.remove_signal_handler(signal.SIGINT)
                wap.save_scan_state()

        if args.max_parameters:
            count = wap.persister.remove_big_requests(args.max_parameters)
            print(_("[*] {0} URLs and forms having more than {1} parameters were removed.".format(
                count,
                args.max_parameters
            )))

        print(_("[*] Wapiti found {0} URLs and forms during the scan").format(wap.count_resources()))
        stop_event.clear()
        loop.add_signal_handler(signal.SIGINT, stop_attack_process)
        await wap.attack(stop_event)
        loop.remove_signal_handler(signal.SIGINT)

    except OperationalError:
        print(_("[!] Can't store information in persister. SQLite database must have been locked by another process"))
        print(_("[!] You should unlock and launch Wapiti again."))
    except SystemExit:
        pass


def wapiti_asyncio_wrapper():
    asyncio.run(wapiti_main())
