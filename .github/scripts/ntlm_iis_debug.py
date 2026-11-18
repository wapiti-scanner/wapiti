"""Trace an NTLM handshake against IIS step by step (temporary, used by the ntlm-iis workflow).

Usage: python ntlm_iis_debug.py URL DOMAIN\\USER PASSWORD
"""
import asyncio
import base64
import logging
import sys

import httpx2
import spnego

from wapitiCore.net.ntlm_auth import HttpNtlmAuth


def describe_token(header_value: str) -> str:
    scheme, _, token = header_value.partition(" ")
    if not token:
        return scheme
    raw = base64.b64decode(token)
    kind = int.from_bytes(raw[8:12], "little") if raw.startswith(b"NTLMSSP\0") else "not NTLMSSP"
    return f"{scheme} <{len(raw)} bytes, message type {kind}>"


async def log_request(request: httpx2.Request):
    print(f"> {request.method} {request.url}")
    for name in ("Connection", "Authorization"):
        if name in request.headers:
            value = request.headers[name]
            print(f">   {name}: {describe_token(value) if name == 'Authorization' else value}")


async def log_response(response: httpx2.Response):
    print(f"< {response.status_code}")
    for value in response.headers.get_list("WWW-Authenticate"):
        print(f"<   WWW-Authenticate: {describe_token(value)}")
    for name in ("Connection", "Content-Length", "Set-Cookie"):
        if name in response.headers:
            print(f"<   {name}: {response.headers[name]}")


async def attempt(url: str, auth: httpx2.Auth, label: str):
    print(f"\n===== {label} =====")
    async with httpx2.AsyncClient(auth=auth, event_hooks={"request": [log_request], "response": [log_response]}) as client:
        response = await client.get(url)
        print(f"final status: {response.status_code}")


async def main():
    url, username, password = sys.argv[1:4]
    print(f"pyspnego {spnego.__version__ if hasattr(spnego, '__version__') else '?'}, platform {sys.platform}")
    probe = spnego.client(username, password, protocol="ntlm")
    print(f"pyspnego context used by default: {type(probe).__name__}")

    await attempt(url, HttpNtlmAuth(username, password), "HttpNtlmAuth (default pyspnego provider)")

    class PurePythonNtlmAuth(HttpNtlmAuth):
        """Same flow, with pyspnego's own NTLM implementation instead of SSPI."""

    original_client = spnego.client

    def pure_python_client(*args, **kwargs):
        kwargs["options"] = spnego.NegotiateOptions.use_ntlm
        return original_client(*args, **kwargs)

    spnego.client = pure_python_client
    try:
        await attempt(url, PurePythonNtlmAuth(username, password), "HttpNtlmAuth (pyspnego pure-Python NTLM)")
    finally:
        spnego.client = original_client


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format="    [%(name)s] %(message)s")
    for noisy in ("asyncio", "hpack"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    asyncio.run(main())
