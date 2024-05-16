#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2006-2023 Nicolas Surribas
# Copyright (C) 2020-2024 Cyberwatch
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
import asyncio
from urllib.parse import urlparse, urlunparse
import argparse
import sys

from wapitiCore.net import jsoncookie
from wapitiCore.net.crawler import AsyncCrawler
from wapitiCore.net.classes import CrawlerConfiguration, HttpCredential, RawCredential
from wapitiCore.parsers.html_parser import Html
from wapitiCore.net import Request
from wapitiCore.net.auth import login_with_raw_data, async_fetch_login_page


class InvalidOptionValue(Exception):
    def __init__(self, opt_name, opt_value):
        super().__init__()
        self.opt_name = opt_name
        self.opt_value = opt_value

    def __str__(self):
        return f"Invalid argument for option {self.opt_name} : {self.opt_value}"


def args_to_crawlerconfiguration(arguments) -> CrawlerConfiguration:
    parts = urlparse(arguments.url)
    base_url = urlunparse((parts.scheme, parts.netloc, parts.path, '', '', ''))
    crawler_configuration = CrawlerConfiguration(Request(base_url))

    if arguments.proxy:
        proxy_parts = urlparse(arguments.proxy)
        if proxy_parts.scheme and proxy_parts.netloc:
            if proxy_parts.scheme.lower() in ("http", "https", "socks", "socks5"):
                crawler_configuration.proxy = arguments.proxy

    if arguments.tor:
        crawler_configuration.proxy = "socks5://127.0.0.1:9050/"

    if "user_agent" in arguments:
        crawler_configuration.user_agent = arguments.user_agent

    if "http_credentials" in arguments:
            # This option is deprecated, but we still support it
            # Should be removed in the future
        if "%" in arguments.http_credentials:
            username, password = arguments.http_credentials.split("%", 1)
            crawler_configuration.http_credential = HttpCredential(username, password, arguments.auth_method)
        else:
            raise InvalidOptionValue("-a", arguments.http_credentials)
    elif "http_user" in arguments and "http_password" in arguments:
        crawler_configuration.http_credential = HttpCredential(arguments.http_user, arguments.http_password,
                                                               arguments.auth_method)

    if ("http_user" in arguments and "http_password" not in arguments) or \
       ("http_user" not in arguments and "http_password" in arguments):
        raise InvalidOptionValue("--auth-user and --auth-password", arguments.http_credentials)


    headers = {}
    for custom_header in arguments.headers:
        if ":" in custom_header:
            hdr_name, hdr_value = custom_header.split(":", 1)
            headers[hdr_name.strip()] = hdr_value.strip()

    if headers:
        crawler_configuration.headers = headers

    return crawler_configuration


async def getcookie_main(arguments):
    parser = argparse.ArgumentParser(description="Wapiti-getcookie: An utility to grab cookies from a webpage")

    parser.add_argument(
        '-u', '--url',
        help='First page to fetch for cookies',
        required=True
    )

    parser.add_argument(
        '-c', '--cookie',
        help='Cookie file in Wapiti JSON format where cookies will be stored',
        required=True
    )

    parser.add_argument(
        '-p', '--proxy',
        help='Address of the proxy server to use'
    )

    parser.add_argument(
        "--tor",
        action="store_true",
        help="Use Tor listener (127.0.0.1:9050)",
    )

    # This option is deprecated
    # Should be removed in a future version
    parser.add_argument(
        "-a", "--auth-cred",
        dest="http_credentials",
        action="store",
        default=argparse.SUPPRESS,
        help="(DEPRECATED) Set HTTP authentication credentials",
        metavar="CREDENTIALS",
    )

    parser.add_argument(
        "--auth-user",
        dest="http_user",
        action="store",
        default=argparse.SUPPRESS,
        help="Set HTTP authentication credentials",
        metavar="USERNAME",
    )

    parser.add_argument(
        "--auth-password",
        dest="http_password",
        action="store",
        default=argparse.SUPPRESS,
        help="Set HTTP authentication credentials",
        metavar="PASSWORD",
    )

    parser.add_argument(
        "--auth-method",
        default="basic",
        help="Set the authentication type to use",
        choices=["basic", "digest", "ntlm"]
    )

    parser.add_argument(
        "--form-data",
        dest="form_data",
        default=argparse.SUPPRESS,
        help="Set login form POST data",
        metavar="DATA"
    )

    parser.add_argument(
        "--form-enctype",
        dest="form_enctype",
        default="application/x-www-form-urlencoded",
        help="Set enctype to use to POST form data to form URL",
        metavar="DATA"
    )

    parser.add_argument(
        "--headless",
        dest="headless",
        default="no",
        help="Use a Firefox headless crawler for browsing (slower)",
        choices=["no", "hidden", "visible"]
    )

    parser.add_argument(
        "-A", "--user-agent",
        default=argparse.SUPPRESS,
        help="Set a custom user-agent to use for every requests",
        metavar="AGENT",
        dest="user_agent"
    )

    parser.add_argument(
        "-H", "--header",
        action="append",
        default=[],
        help="Set a custom header to use for every requests",
        metavar="HEADER",
        dest="headers"
    )

    args = parser.parse_args(arguments)

    parts = urlparse(args.url)
    if not parts.scheme or not parts.netloc or not parts.path:
        print("Invalid base URL was specified, please give a complete URL with protocol scheme"
              " and slash after the domain name.")
        sys.exit()

    server = parts.netloc
    crawler_configuration = args_to_crawlerconfiguration(args)

    # Open or create the cookie file and delete previous cookies from this server
    json_cookie = jsoncookie.JsonCookie()
    json_cookie.load(args.cookie)
    json_cookie.delete(server)

    page_source = await async_fetch_login_page(crawler_configuration, args.url, args.headless)
    json_cookie.addcookies(crawler_configuration.cookies)

    if "form_data" in args:
        raw_credential = RawCredential(
            args.form_data,
            args.url,
            args.form_enctype
        )
        await login_with_raw_data(crawler_configuration, raw_credential)
        json_cookie.addcookies(crawler_configuration.cookies)
    else:
        # Not data specified, try interactive mode by fetching forms
        forms = []
        html = Html(page_source, args.url)
        for i, form in enumerate(html.iter_forms(autofill=False)):
            if i == 0:
                print('')
                print("Choose the form you want to use or enter 'q' to leave :")
            print(f"{i}) {form}")
            forms.append(form)

        valid_choice_done = False
        if forms:
            nchoice = -1
            print('')
            while not valid_choice_done:
                choice = input("Enter a number : ")
                if choice.isdigit():
                    nchoice = int(choice)
                    if len(forms) > nchoice >= 0:
                        valid_choice_done = True
                elif choice == 'q':
                    break

            if valid_choice_done:
                form = forms[nchoice]
                print('')
                print("Please enter values for the following form: ")
                print(f"url = {form.url}")

                post_params = form.post_params
                for i, post_param_tuple in enumerate(post_params):
                    field, value = post_param_tuple
                    if value:
                        new_value = input(field + " (" + value + ") : ")
                        if not new_value:
                            new_value = value
                    else:
                        new_value = input(f"{field}: ")
                    post_params[i] = [field, new_value]

                request = Request(form.url, post_params=post_params)
                async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
                    await crawler.async_send(request, follow_redirects=True)
                    json_cookie.addcookies(crawler.cookie_jar)

    json_cookie.dump()


def getcookie_asyncio_wrapper():
    asyncio.run(getcookie_main(sys.argv[1:]))
