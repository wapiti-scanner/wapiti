# This is just a rewrite of the mitmproxy stickycookie addon with async methods
import asyncio
import collections
from http import cookiejar
from typing import List, Tuple, Dict  # noqa

from mitmproxy import http
from mitmproxy.net.http import cookies

TOrigin = Tuple[str, int, str]


def ckey(attrs: Dict[str, str], f: http.HTTPFlow) -> TOrigin:
    """
        Returns a (domain, port, path) tuple.
    """
    domain = f.request.host
    path = "/"
    if "domain" in attrs:
        domain = attrs["domain"]
    if "path" in attrs:
        path = attrs["path"]
    return domain, f.request.port, path


def domain_match(a: str, b: str) -> bool:
    if cookiejar.domain_match(a, b):  # type: ignore
        return True
    if cookiejar.domain_match(a, b.strip(".")):  # type: ignore
        return True
    return False


class AsyncStickyCookie:
    def __init__(self):
        self.jar: Dict[TOrigin, Dict[str, str]] = collections.defaultdict(dict)

    async def response(self, flow: http.HTTPFlow):
        await asyncio.sleep(.1)
        for name, (value, attrs) in flow.response.cookies.items(multi=True):
            # valid RFC 822/1123 datetime specifications for expiry. Sigh.
            dom_port_path = ckey(attrs, flow)

            if domain_match(flow.request.host, dom_port_path[0]):
                if cookies.is_expired(attrs):
                    # Remove the cookie from jar
                    self.jar[dom_port_path].pop(name, None)

                    # If all cookies of a dom_port_path have been removed
                    # then remove it from the jar itself
                    if not self.jar[dom_port_path]:
                        self.jar.pop(dom_port_path, None)
                else:
                    self.jar[dom_port_path][name] = value

    async def request(self, flow: http.HTTPFlow):
        await asyncio.sleep(.1)
        cookie_list: List[Tuple[str, str]] = []
        for (domain, port, path), c in self.jar.items():
            match = [
                domain_match(flow.request.host, domain),
                flow.request.port == port,
                flow.request.path.startswith(path)
            ]
            if all(match):
                cookie_list.extend(c.items())
        if cookie_list:
            flow.metadata["stickycookie"] = True
            flow.request.headers["cookie"] = cookies.format_cookie_header(cookie_list)
