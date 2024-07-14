#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2021-2023 Nicolas Surribas
# Copyright (C) 2021-2024 Cyberwatch
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
import json
import os
from typing import List, Iterator, Set, Optional
import re
from itertools import cycle
from functools import lru_cache
import socket
from random import shuffle

import httpx
from tld import get_fld
from tld.exceptions import TldDomainNotFound, TldBadUrl
import dns.asyncresolver
import dns.exception
import dns.name
import dns.resolver

from wapitiCore.main.log import log_red, logging, log_verbose
from wapitiCore.net import Request, Response
from wapitiCore.attack.attack import Attack
from wapitiCore.definitions.subdomain_takeovers import SubdomainTakeoverFinding


FINGERPRINTS_FILENAME = "takeover_fingerprints.json"
RESOLVERS_FILENAME = "resolvers.txt"
SUBDOMAINS_FILENAME = "subdomain-wordlist.txt"

GITHUB_IO_REGEX = re.compile(r"([a-z0-9]+)\.github\.io$")
MY_SHOPIFY_REGEX = re.compile(r"([a-z0-9-]+)\.myshopify\.com$")
IPV4_REGEX = re.compile(r"(\d+)\.(\d+)\.(\d+)\.(\d+)$")

CONCURRENT_TASKS = 100  # We can afford more concurrent tasks than for HTTP


@lru_cache(maxsize=2000)
def get_root_domain(domain: str):
    # May raise tld.exceptions.TldDomainNotFound, tld.exceptions.TldBadUrl
    return get_fld(domain, fix_protocol=True)


class TakeoverChecker:
    def __init__(self):
        with open(os.path.join(Attack.DATA_DIR, FINGERPRINTS_FILENAME), errors="ignore", encoding='utf-8') as fd:
            data = json.load(fd)
            self.ignore = []
            for ignore_regex in data["ignore"]:
                self.ignore.append(re.compile(r"(" + ignore_regex + r")"))
            self.services = data["services"]

    @staticmethod
    async def check_content(subdomain: str, fingerprints: List[str]) -> bool:
        if fingerprints:
            async with httpx.AsyncClient() as client:
                results = await asyncio.gather(
                    client.get(f"http://{subdomain}/", timeout=10),
                    client.get(f"https://{subdomain}/", timeout=10),
                    return_exceptions=True
                )
                for result in results:
                    if isinstance(result, BaseException):
                        continue
                    for pattern in fingerprints:
                        if pattern in result.text:
                            return True

        return False

    async def check(self, origin: str, domain: str) -> bool:
        if "." not in domain or domain.endswith((".local", ".internal")):
            # Stuff like "localhost": internal CNAMEs we can't control
            return False

        # Check for known false positives first
        for regex in self.ignore:
            if regex.search(domain):
                return False

        if IPV4_REGEX.match(domain):
            # Obviously we can't take control over any IP on the Internet
            return False

        # Is the pointed domain part of some particular takeover case?
        for service_entry in self.services:
            for cname_regex in service_entry["cname"]:
                if re.search(cname_regex, domain):
                    # The pointed domain match one of the rules, check the content on the website if necessary
                    result = await self.check_content(origin, service_entry["fingerprint"])
                    if result:
                        search = GITHUB_IO_REGEX.search(domain)
                        if search:
                            # This is a github.io website, we need to check is the username/organization exists
                            username = search.group(1)
                            try:
                                async with httpx.AsyncClient() as client:
                                    response = await client.head(f"https://github.com/{username}", timeout=10.)
                                    if response.is_client_error:
                                        return True
                            except httpx.RequestError:
                                logging.warning(f"HTTP request to https://github.com/{username} failed")
                            return False

                        search = MY_SHOPIFY_REGEX.search(domain)
                        if search:
                            # Check for myshopify false positives
                            shop_name = search.group(1)
                            try:
                                async with httpx.AsyncClient() as client:
                                    # Tip from https://github.com/buckhacker/SubDomainTakeoverTools
                                    response = await client.get(
                                        (
                                            "https://app.shopify.com/services/signup/check_availability.json?"
                                            f"shop_name={shop_name}&email=test@example.com"
                                        ),
                                        timeout=10.
                                    )
                                    data = response.json()
                                    if data["status"] == "available":
                                        return True
                            except httpx.RequestError:
                                logging.warning("HTTP request to Shopify API failed")

                            return False

                        return True

                    # Otherwise if the pointed domain doesn't exist it may be enough
                    if service_entry["nxdomain"]:
                        try:
                            await dns.asyncresolver.resolve(domain)
                        except dns.asyncresolver.NXDOMAIN:
                            return True
                        except BaseException:
                            continue

        # What remains is potentially unregistered domain.
        # First: get root domain of the pointed domain
        try:
            root_domain = get_root_domain(domain)
        except (TldDomainNotFound, TldBadUrl):
            # We can't register the pointed domain as it is invalid
            logging.warning(f"Pointed domain {domain} is not a valid domain name")
            return False

        try:
            # Second: using SOA on this root domain we check if it is available
            await dns.asyncresolver.resolve(root_domain, "SOA", raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            return True
        except BaseException as exception:
            logging.warning(f"ANY request for {root_domain}: {exception}")

        return False


def load_resolvers() -> List[str]:
    with open(os.path.join(Attack.DATA_DIR, RESOLVERS_FILENAME), errors="ignore", encoding='utf-8') as fd:
        resolvers = [ip.strip() for ip in fd.readlines() if ip.strip()]
        shuffle(resolvers)
        return resolvers


async def get_wildcard_responses(domain: str, resolvers: Iterator[str]) -> List[str]:
    # Ask for an improbable subdomain to see if there are any responses
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 10.
    resolver.nameservers = [next(resolvers) for __ in range(10)]

    try:
        results = await resolver.resolve(f"supercalifragilisticexpialidocious.{domain}", "CNAME")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout, dns.resolver.NoNameservers):
        return []
    return [record.to_text().strip(".") for record in results]


class ModuleTakeover(Attack):
    """Detect subdomains vulnerable to takeover (CNAME records pointing to non-existent and/or available domains)"""
    name = "takeover"

    def __init__(self, crawler, persister, attack_options, stop_event, crawler_configuration):
        super().__init__(crawler, persister, attack_options, stop_event, crawler_configuration)
        self.processed_domains = set()
        self.takeover = TakeoverChecker()

    async def must_attack(self, request: Request, response: Optional[Response] = None):
        try:
            root_domain = get_root_domain(request.hostname)
        except (TldDomainNotFound, TldBadUrl):
            # If the hostname part is an IP or is invalid we can't do subdomain enumeration obviously
            return False
        if response.is_directory_redirection:
            return False

        if root_domain in self.processed_domains:
            return False

        self.processed_domains.add(root_domain)
        return True

    async def feed_queue(self, queue: asyncio.Queue, domain: str):
        with open(os.path.join(self.DATA_DIR, SUBDOMAINS_FILENAME), errors="ignore", encoding='utf-8') as fd:
            for line in fd:
                sub = line.strip()

                if not sub:
                    continue

                while True:
                    try:
                        queue.put_nowait(f"{sub}.{domain}")
                    except asyncio.QueueFull:
                        await asyncio.sleep(.01)
                    else:
                        break

                if self._stop_event.is_set():
                    break

        # send stop command to every worker
        for __ in range(CONCURRENT_TASKS):
            while True:
                try:
                    queue.put_nowait("__exit__")
                except asyncio.QueueFull:
                    await asyncio.sleep(.01)
                else:
                    break

    async def worker(self, queue: asyncio.Queue, resolvers: Iterator[str], root_domain: str, bad_responses: Set[str]):
        while True:
            try:
                domain = queue.get_nowait().strip()
            except asyncio.QueueEmpty:
                await asyncio.sleep(.05)
            else:
                queue.task_done()
                if domain == "__exit__":
                    break

                try:
                    resolver = dns.asyncresolver.Resolver()
                    resolver.timeout = 10.
                    resolver.nameservers = [next(resolvers) for __ in range(10)]
                    answers = await resolver.resolve(domain, 'CNAME', raise_on_no_answer=False)
                except (socket.gaierror, UnicodeError):
                    continue
                except (dns.asyncresolver.NXDOMAIN, dns.exception.Timeout):
                    continue
                except (dns.name.EmptyLabel, dns.resolver.NoNameservers) as exception:
                    logging.warning(f"{domain}: {exception}")
                    continue

                for answer in answers:
                    cname = answer.to_text().strip(".")

                    if cname in bad_responses:
                        continue

                    log_verbose(f"Record {domain} points to {cname}")

                    try:
                        if get_root_domain(cname) == root_domain:
                            # If it is an internal CNAME (like www.target.tld to target.tld) just ignore
                            continue
                    except (TldDomainNotFound, TldBadUrl):
                        logging.warning(f"{cname} is not a valid domain name")
                        continue

                    if await self.takeover.check(domain, cname):
                        log_red("---")
                        log_red(f"CNAME {domain} to {cname} seems vulnerable to takeover")
                        log_red("---")

                        await self.add_high(
                            finding_class=SubdomainTakeoverFinding,
                            info=f"CNAME {domain} to {cname} seems vulnerable to takeover",
                            request=Request(f"https://{domain}/"),
                        )

    async def attack(self, request: Request, response: Optional[Response] = None):
        tasks = []
        sub_queue = asyncio.Queue(maxsize=CONCURRENT_TASKS)
        tasks.append(asyncio.create_task(self.feed_queue(sub_queue, request.hostname)))

        resolvers = load_resolvers()
        resolvers_cycle = cycle(resolvers)
        wildcard_responses = await get_wildcard_responses(request.hostname, resolvers_cycle)
        for __ in range(CONCURRENT_TASKS):
            tasks.append(
                asyncio.create_task(self.worker(sub_queue, resolvers_cycle, request.hostname, set(wildcard_responses)))
            )

        await asyncio.gather(*tasks)
