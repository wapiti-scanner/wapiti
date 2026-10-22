#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2023-2026 Nicolas SURRIBAS
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
import json
from http.cookiejar import CookieJar
from typing import Tuple, List, Dict, Optional
import asyncio
from urllib.parse import urljoin
import importlib.util

from httpx import RequestError
from tld import get_fld
from tld.exceptions import TldDomainNotFound
# pylint: disable=protected-access
from playwright._impl._errors import TargetClosedError
from playwright.async_api import async_playwright, Error as PlaywrightError

from wapitiCore.net import Request, Response
from wapitiCore.parsers.html_parser import Html
from wapitiCore.main.log import logging, log_green, log_orange
from wapitiCore.net.classes import CrawlerConfiguration, FormCredential, RawCredential
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.net.cookies import headless_cookies_to_cookiejar
from wapitiCore.net.scope import Scope
from wapitiCore.net.web import urlparse

DEFAULT_PORTS = {"http": 80, "https": 443}


def _host_and_port(url: str) -> Tuple[Optional[str], Optional[int]]:
    parts = urlparse(url)
    return parts.hostname, parts.port or DEFAULT_PORTS.get(parts.scheme)


def _registrable_domain(url: str) -> Optional[str]:
    try:
        return get_fld(url)
    except TldDomainNotFound:
        # IP address, localhost, internal name...
        return None


def is_login_destination_allowed(login_url: str, page_url: str, scope: Optional[Scope] = None) -> bool:
    """Tell whether credentials may be submitted to login_url, given the URL of the page holding the form.

    The page content is untrusted (HTML injection, compromised target...) and chooses the form action, so
    credentials only go to the host and port serving the login page, another host of its registrable domain
    (www.example.com -> accounts.example.com) or a URL within the scan scope. Anything else is refused.
    """
    login_host, login_port = _host_and_port(login_url)
    if not login_host:
        return False

    if (login_host, login_port) == _host_and_port(page_url):
        return True

    login_domain = _registrable_domain(login_url)
    if login_domain and login_domain == _registrable_domain(page_url):
        return True

    return scope is not None and scope.check(login_url)


async def check_http_auth(crawler_configuration: CrawlerConfiguration) -> bool:
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        response = await crawler.async_get(crawler_configuration.base_request)

        if response.status in (401, 403, 404):
            return False
        return True


def _create_login_request(
        login_form: Request, username, username_field_idx, password, password_field_idx
) -> Tuple[Request, Dict]:
    form = {}
    post_params = login_form.post_params
    get_params = login_form.get_params

    if login_form.method == "POST":
        post_params[username_field_idx][1] = username
        post_params[password_field_idx][1] = password
        form["login_field"] = post_params[username_field_idx][0]
        form["password_field"] = post_params[password_field_idx][0]
    else:
        get_params[username_field_idx][1] = username
        get_params[password_field_idx][1] = password
        form["login_field"] = get_params[username_field_idx][0]
        form["password_field"] = get_params[password_field_idx][0]

    login_request = Request(
        path=login_form.url,
        method=login_form.method,
        post_params=post_params,
        get_params=get_params,
        referer=login_form.referer,
        link_depth=login_form.link_depth
    )

    return login_request, form


async def async_fetch_login_page(
        crawler_configuration: CrawlerConfiguration,
        url: str,
        headless_mode: str = "no",
) -> Tuple[Optional[str], Optional[str]]:
    """
    Fetch the login page at url, keeping the cookies set along the way.
    Returns the page source and the URL it was finally served from (after redirects), or (None, None) on error.
    """
    # Step 1: Fetch the login page and try to extract the login form, keep cookies too
    if headless_mode != "no":
        proxy_settings = None
        if crawler_configuration.proxy:
            proxy_settings = {"server": crawler_configuration.proxy}

        try:
            async with async_playwright() as p:
                browser = await p.firefox.launch(
                    headless=headless_mode == "hidden",
                    proxy=proxy_settings,
                    firefox_user_prefs={
                        "network.proxy.allow_hijacking_localhost": True,
                        "devtools.jsonview.enabled": False,
                    }
                )
                context = await browser.new_context(ignore_https_errors=True)
                page = await context.new_page()

                try:
                    await page.goto(
                        url,
                        timeout=crawler_configuration.timeout * 1000,
                        wait_until="domcontentloaded"
                    )
                    await page.wait_for_timeout(100)
                    page_source = await page.content()
                    page_url = page.url
                    crawler_configuration.cookies = headless_cookies_to_cookiejar(await context.cookies())
                    return page_source, page_url
                finally:
                    await browser.close()

        except (PlaywrightError, asyncio.TimeoutError) as exception:
            if isinstance(exception, TargetClosedError):
                return None, None

            logging.error("[!] %s with URL %s", type(exception).__name__, url)
            return None, None
    else:
        async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
            try:
                response: Response = await crawler.async_get(
                    Request(url),
                    follow_redirects=True
                )
                crawler_configuration.cookies = crawler.cookie_jar
                return response.content, response.url
            except ConnectionError:
                logging.error("[!] Connection error with URL %s", url)
                return None, None
            except RequestError as exception:
                logging.error(
                    "[!] %s with URL %s", type(exception).__name__, url
                )
                return None, None


async def async_submit_login_form(
        page_source: str,
        crawler_configuration: CrawlerConfiguration,
        form_credential: FormCredential,
        page_url: Optional[str] = None,
        scope: Optional[Scope] = None,
) -> Tuple[bool, dict, List[str]]:
    """Find the login form in page_source and submit the credentials to it.

    page_url is the URL the page was actually served from (defaults to the one given by the user) and
    scope the scan scope: both decide where the credentials may be sent, see is_login_destination_allowed.
    """
    disconnect_urls = []
    page_url = page_url or form_credential.url
    page = Html(page_source, page_url)

    login_form, username_field_idx, password_field_idx = page.find_login_form()
    if login_form and not is_login_destination_allowed(login_form.url, page_url, scope):
        logging.error(
            "[!] Login failed : the login form submits to %s, outside of the login page host and the scan scope. "
            "Refusing to send the credentials there.",
            urlparse(login_form.url).netloc
        )
        return False, {}, []

    if login_form:
        if urlparse(page_url).scheme == "https" and urlparse(login_form.url).scheme == "http":
            log_orange("[!] The login form submits the credentials over plain HTTP to %s", login_form.url)

        # Step 2: submit the login form, keep new cookies
        login_request, form = _create_login_request(
            login_form,
            form_credential.username,
            username_field_idx,
            form_credential.password,
            password_field_idx,
        )

        async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
            login_response = await crawler.async_send(
                login_request,
                follow_redirects=True
            )

            html = Html(login_response.content, login_response.url)

            # ensure logged in
            is_logged_in = html.is_logged_in()
            if is_logged_in:
                log_green("[*] Login success")
                disconnect_urls = html.extract_disconnect_urls()
            else:
                log_orange("[!] Login failed : Credentials might be invalid")

            # In every case keep the cookies
            crawler_configuration.cookies = crawler.cookie_jar
            return is_logged_in, form, disconnect_urls

    logging.warning("[!] Login failed : No login form detected")
    return False, {}, []


async def async_try_form_login(
        crawler_configuration: CrawlerConfiguration,
        form_credential: FormCredential,
        headless_mode: str = "no",
        scope: Optional[Scope] = None,
) -> Tuple[bool, dict, List[str]]:
    """
    Try to authenticate with the provided url and credentials.
    Returns if the authentication has been successful, the used form variables and the disconnect urls.
    """
    page_source, page_url = await async_fetch_login_page(crawler_configuration, form_credential.url, headless_mode)
    if not page_source:
        return False, {}, []

    if urlparse(page_url).hostname != urlparse(form_credential.url).hostname:
        # Legitimate with an external identity provider, but the operator must know where the credentials go
        log_orange(
            "[!] Login page %s redirected to %s, credentials will be submitted to that host",
            form_credential.url,
            page_url
        )

    return await async_submit_login_form(page_source, crawler_configuration, form_credential, page_url, scope)


async def login_with_raw_data(crawler_configuration: CrawlerConfiguration, raw_credential: RawCredential):
    """Performs authentication by directly sending POST request with raw data"""
    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        login_request = Request(
            raw_credential.url,
            post_params=raw_credential.data,
            enctype=raw_credential.enctype,
        )
        await crawler.async_send(
            login_request,
            follow_redirects=True
        )
        crawler_configuration.cookies = crawler.cookie_jar


async def load_form_script(
        filepath: str,
        crawler_configuration: CrawlerConfiguration,
        form_credential: Optional[FormCredential] = None,
        headless: str = "no"
):
    """Load the Python script at filepath and call the run function in it with several parameters"""
    spec = importlib.util.spec_from_file_location("plugin", filepath)

    try:
        module = importlib.util.module_from_spec(spec)
    except (FileNotFoundError, AttributeError):
        logging.error("Unable to load auth script '%s'. Check path, access rights or syntax.", filepath)
        sys.exit(1)

    spec.loader.exec_module(module)
    # We expect the auth script to set cookies on the crawler_configuration object, but everything can be done here
    try:
        await module.run(crawler_configuration, form_credential, headless)
    except AttributeError:
        logging.error("run() method seems to be missing in your auth script")
        sys.exit(1)
    except TypeError as exception:
        raise RuntimeError("The provided auth script seems to have some syntax issues") from exception

def _get_selector(target: str) -> str:
    if target.startswith("id="):
        return f"#{target.split('=', 1)[1]}"
    if target.startswith("css="):
        return target.split('=', 1)[1]
    if target.startswith("xpath="):
        return target.split('=', 1)[1]
    return target


async def authenticate_with_side_file(
        crawler_configuration: CrawlerConfiguration,
        side_file_path: str,
        headless_value: str
) -> Optional[CookieJar]:
    """
    Authenticate using a .side file.
    """
    # Load and parse the .side file
    try:
        # Attempt to open the file
        with open(side_file_path, 'r', encoding='utf-8') as file:
            # Load JSON data from the file
            try:
                side_data = json.load(file)
            except json.JSONDecodeError:
                logging.error("The file content is not valid JSON.")
                sys.exit(1)


    except (FileNotFoundError, AttributeError):
        logging.error("Unable to load auth script '%s'. Check path, access rights or syntax.", side_file_path)
        sys.exit(1)


    url = side_data['url']
    login_test = side_data['tests'][0]  # Assuming the first test is the login test

    proxy_settings = None
    if crawler_configuration.proxy:
        proxy_settings = {"server": crawler_configuration.proxy}

    try:
        async with async_playwright() as p:
            browser = await p.firefox.launch(
                headless=headless_value in ["hidden", "no"],
                proxy=proxy_settings,
                firefox_user_prefs={
                    "network.proxy.allow_hijacking_localhost": True,
                    "devtools.jsonview.enabled": False,
                }
            )
            context = await browser.new_context(ignore_https_errors=True)
            page = await context.new_page()

            try:
                for command in login_test['commands']:
                    await asyncio.sleep(3)
                    cmd = command['command']
                    target = command['target']
                    value = command.get('value', '')

                    if cmd == "open":
                        await page.goto(urljoin(url, target))

                    elif cmd == "type":
                        selector = _get_selector(target)
                        await page.fill(selector, value)

                    elif cmd == "click":
                        selector = _get_selector(target)
                        await page.click(selector)

                await page.wait_for_timeout(100)
                crawler_configuration.cookies = headless_cookies_to_cookiejar(await context.cookies())

                return crawler_configuration.cookies
            finally:
                await browser.close()

    except (PlaywrightError, asyncio.TimeoutError) as exception:
        if isinstance(exception, TargetClosedError):
            return None

        logging.error("[!] %s with URL %s", type(exception).__name__, url)
        return None
