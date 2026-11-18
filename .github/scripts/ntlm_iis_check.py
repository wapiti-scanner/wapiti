"""Check wapiti's NTLM authentication against a real IIS (used by the ntlm-iis workflow).

Usage: python ntlm_iis_check.py URL DOMAIN\\USER PASSWORD
"""
import asyncio
import sys

from wapitiCore.net import Request
from wapitiCore.net.classes import CrawlerConfiguration, HttpCredential
from wapitiCore.net.crawler import AsyncCrawler


async def fetch_statuses(url: str, username: str, password: str, count: int) -> list:
    configuration = CrawlerConfiguration(
        Request(url),
        timeout=10,
        # Lets the workflow tell these requests apart from the wapiti scan in the IIS logs
        user_agent="wapiti-ntlm-check",
        http_credential=HttpCredential(username, password, "ntlm"),
    )
    async with AsyncCrawler.with_configuration(configuration) as crawler:
        # Sequential requests reuse the authenticated connection
        statuses = [(await crawler.async_get(Request(url))).status for _ in range(3)]
        # Concurrent requests open several connections, each one needs its own handshake
        responses = await asyncio.gather(*(crawler.async_get(Request(url)) for _ in range(count)))
        return statuses + [response.status for response in responses]


async def main() -> int:
    url, username, password = sys.argv[1:4]

    good = await fetch_statuses(url, username, password, 30)
    print(f"valid credentials: {good}")
    bad = await fetch_statuses(url, username, password + "-wrong", 2)
    print(f"wrong password: {bad}")

    if set(good) != {200}:
        print("FAIL: authentication with valid credentials did not always succeed")
        return 1
    if set(bad) != {401}:
        print("FAIL: a wrong password was not rejected with a 401")
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
