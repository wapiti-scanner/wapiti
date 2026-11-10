"""Persistence of the CSP posture deduplication state across a scanner restart.

The passive scanner and the SQLite persister are the real implementations; only the
HTTP exchange is synthetic, so no network access is needed.
"""
import asyncio

import httpx

from wapitiCore.attack.passive_scanner import PassiveScanner
from wapitiCore.net import Request, Response
from wapitiCore.net.sql_persister import SqlPersister

POLICY_A = (
    "script-src 'self' 'unsafe-inline'; img-src data:; object-src 'none'; "
    "base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
)
# Same directives, but 'unsafe-inline' and 'data:' are attached to the other directive.
POLICY_B = (
    "script-src 'self' data:; img-src 'unsafe-inline'; object-src 'none'; "
    "base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
)
BASE_URL = "http://example.test/"


def _make_response(url: str, policy: str) -> tuple:
    request = Request(url)
    response = Response(
        httpx.Response(
            200,
            headers={"Content-Type": "text/html", "Content-Security-Policy": policy},
            content=b"<html></html>",
        ),
        url=request.url,
    )
    return request, response


async def _scan(scanner: PassiveScanner, path: str, policy: str) -> None:
    request, response = _make_response(BASE_URL + path, policy)
    await scanner.scan(request, response)


def _new_scanner(persister: SqlPersister) -> PassiveScanner:
    scanner = PassiveScanner(persister=persister)
    assert "csp" in scanner._modules
    scanner.set_modules({"csp": []})
    return scanner


def test_csp_posture_deduplication_survives_a_restart(tmp_path):
    db_path = tmp_path / "csp-posture.db"

    async def scenario():
        persister = SqlPersister(str(db_path))
        await persister.create()
        scanner = _new_scanner(persister)
        try:
            await _scan(scanner, "first", POLICY_A)
            await scanner.persist_state()
            first_run = [payload async for payload in persister.get_payloads()]
        finally:
            await persister.close()
        assert len(first_run) == 2

        persister = SqlPersister(str(db_path))
        await persister.create()
        scanner = _new_scanner(persister)
        try:
            await scanner.restore_state()
            # Same policy on another URL: already reported before the restart.
            await _scan(scanner, "equivalent", POLICY_A)
            after_restart = [payload async for payload in persister.get_payloads()]
            assert len(after_restart) == 2

            await _scan(scanner, "distinct", POLICY_B)
            await scanner.persist_state()
            rows = [payload async for payload in persister.get_payloads()]
            suppressed = await persister.get_suppressed_findings()

            # Re-serving the second policy must stay suppressed too.
            await _scan(scanner, "distinct-again", POLICY_B)
            repeated = [payload async for payload in persister.get_payloads()]
        finally:
            await persister.close()

        assert [row.evil_request.url for row in rows] == [
            BASE_URL + "first",
            BASE_URL + "first",
            BASE_URL + "distinct",
            BASE_URL + "distinct",
        ]
        return rows, suppressed, repeated

    rows, suppressed, repeated = asyncio.run(scenario())

    assert len(repeated) == 4
    assert suppressed == {"Content Security Policy Configuration": 2}
    infos = [row.info for row in rows]
    assert infos.count(f'CSP attribute "default-src" is missing for URL: {BASE_URL}first') == 1
    assert infos.count(f'CSP "script-src" value is not safe for URL: {BASE_URL}distinct') == 1
