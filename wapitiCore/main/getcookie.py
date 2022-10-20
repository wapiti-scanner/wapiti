#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2006-2022 Nicolas Surribas
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
from wapitiCore.net.classes import CrawlerConfiguration, HttpCredential
from wapitiCore.parsers.html import Html
from wapitiCore.net import Request
from wapitiCore.net.response import Response


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
        if "%" in arguments.http_credentials:
            username, password = arguments.http_credentials.split("%", 1)
            crawler_configuration.http_credential = HttpCredential(username, password)
        else:
            raise InvalidOptionValue("-a", arguments.http_credentials)

    if "auth_method" in arguments:
        crawler_configuration.auth_method = arguments.auth_method

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

    parser.add_argument(
        "-a", "--auth-cred",
        dest="http_credentials",
        default=argparse.SUPPRESS,
        help="Set HTTP authentication credentials",
        metavar="CREDENTIALS",
    )

    parser.add_argument(
        "--auth-method",
        default=argparse.SUPPRESS,
        help="Set the authentication type to use",
        choices=["basic", "digest", "ntlm"]
    )

    parser.add_argument(
        '-d', '--data',
        help='Data to send to the form with POST'
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

    async with AsyncCrawler.with_configuration(crawler_configuration) as crawler:
        response: Response = await crawler.async_get(Request(args.url), follow_redirects=True)

        # A first crawl is sometimes necessary, so let's fetch the webpage
        json_cookie.addcookies(crawler.cookie_jar)

        if not args.data:
            # Not data specified, try interactive mode by fetching forms
            forms = []
            html = Html(response.content, args.url)
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
                    await crawler.async_send(request, follow_redirects=True)

                    json_cookie.addcookies(crawler.cookie_jar)
        else:
            request = Request(args.url, post_params=args.data)
            await crawler.async_send(request, follow_redirects=True)

            json_cookie.addcookies(crawler.cookie_jar)

        json_cookie.dump()


def getcookie_asyncio_wrapper():
    asyncio.run(getcookie_main(sys.argv[1:]))
