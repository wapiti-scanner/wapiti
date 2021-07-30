import asyncio
import json
import os
from typing import Tuple, List, Iterator
import re
import sys
from itertools import cycle
import socket
from random import shuffle

import httpx
from httpx import RequestError
from tld import get_fld
from tld.exceptions import TldDomainNotFound
import dns.asyncresolver
import dns.exception
import dns.name
import dns.resolver
from loguru import logger as log

from wapitiCore.net.web import Request
from wapitiCore.attack.attack import Attack
from wapitiCore.language.vulnerability import _


FINGERPRINTS_FILENAME = "takeover_fingerprints.json"
RESOLVERS_FILENAME = "resolvers.txt"
SUBDOMAINS_FILENAME = "subdomain-wordlist.txt"

GITHUB_IO_REGEX = re.compile(r"([a-z0-9]+)\.github\.io$")
MY_SHOPIFY_REGEX = re.compile(r"([a-z0-9-]+)\.myshopify\.com$")

BASE_DIR = os.path.dirname(sys.modules["wapitiCore"].__file__)
DATA_DIR = os.path.join(BASE_DIR, "data", "attacks")

CONCURRENT_TASKS = 100  # We can afford more concurrent tasks than for HTTP


class Takeover:
    def __init__(self):
        with open(os.path.join(DATA_DIR, FINGERPRINTS_FILENAME), errors="ignore") as fd:
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
        # Check for known false positives first
        for regex in self.ignore:
            if regex.search(domain):
                return False

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
                                    if response.status_code == 404:
                                        return True
                            except httpx.RequestError as exception:
                                log.warning(f"HTTP request to https://github.com/{username} failed")
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
                            except httpx.RequestError as exception:
                                log.warning(f"HTTP request to Shopify API failed")

                            return False

                        return True

                    # Otherwise if the pointed domain doesn't exists if may be enough
                    if service_entry["nxdomain"]:
                        try:
                            await dns.asyncresolver.resolve(domain)
                        except dns.asyncresolver.NXDOMAIN:
                            return True
                        except BaseException:
                            continue

        root_domain = get_fld(domain, fix_protocol=True)
        try:
            # We use this request to see if this is an unregistered domain
            answers = await dns.asyncresolver.resolve(root_domain, "SOA", raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            return True
        except BaseException as exception:
            log.warning(f"ANY request for {root_domain}: {exception}")

        return False


async def feed_queue(queue: asyncio.Queue, domain: str, event: asyncio.Event):
    with open(os.path.join(DATA_DIR, SUBDOMAINS_FILENAME), errors="ignore") as fd:
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

            if event.is_set():
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

takeover = Takeover()


def load_resolvers() -> List[str]:
    with open(os.path.join(DATA_DIR, RESOLVERS_FILENAME), errors="ignore") as fd:
        resolvers = [ip.strip() for ip in fd.readlines() if ip.strip()]
        shuffle(resolvers)
        return resolvers


async def worker(queue: asyncio.Queue, resolvers: Iterator[str], root_domain: str, verbose: bool = True):
    global takeover

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
            except (dns.asyncresolver.NXDOMAIN, dns.exception.Timeout) as exception:
                # print(f"{domain}: {exception}")
                continue
            except (dns.name.EmptyLabel, dns.resolver.NoNameservers) as exception:
                log.warning(f"{domain}: {exception}")
                continue

            for answer in answers:
                cname = answer.to_text().strip(".")
                if verbose:
                    log.info(f"Record {domain} points to {cname}")

                try:
                    if get_fld(cname, fix_protocol=True) == root_domain:
                        # If it is an internal CNAME (like www.target.tld to target.tld) just ignore
                        continue
                except TldDomainNotFound:
                    log.warning(f"{cname} is not a valid domain name")
                    continue

                if await takeover.check(domain, cname):
                    log.critical(f"{domain} to {cname} CNAME seems vulnerable to takeover")


class mod_takeover(Attack):
    """Detect subdomains vulnerable to takeover (CNAME records pointing to non-existent and/or available domains)"""
    name = "takeover"
    processed_domains = set()

    async def must_attack(self, request: Request):
        root_domain = get_fld(request.hostname, fix_protocol=True)
        if root_domain in self.processed_domains:
            return False

        return True

    async def attack(self, request: Request):
        root_domain = get_fld(request.hostname, fix_protocol=True)

        tasks = []

        sub_queue = asyncio.Queue(maxsize=CONCURRENT_TASKS)
        tasks.append(asyncio.create_task(feed_queue(sub_queue, root_domain, self._stop_event)))

        resolvers = load_resolvers()
        resolvers_cycle = cycle(resolvers)
        for __ in range(CONCURRENT_TASKS):
            tasks.append(
                asyncio.create_task(worker(sub_queue, resolvers_cycle, root_domain))
            )

        await asyncio.gather(*tasks)

        # TODO: log things properly / add vulnerabilities to report / add definitions for subdomain takeovers
        #     await self.detect_version(request_to_root.url)
        #     self.versions = sorted(self.versions, key=lambda x: x.split('.')) if self.versions else [""]
        #     drupal_detected = {
        #         "name": "Drupal",
        #         "versions": self.versions,
        #         "categories": ["CMS Drupal"]
        #     }
        #     self.log_blue(
        #         MSG_TECHNO_VERSIONED,
        #         "Drupal",
        #         self.versions
        #     )
        #     await self.add_addition(
        #         category=TECHNO_DETECTED,
        #         request=request_to_root,
        #         info=json.dumps(drupal_detected),
        #     )

