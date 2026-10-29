"""Genuine persist / close / reopen / restore regression for the https_redirect gate.

A safe HTTP -> HTTPS redirect is not a finding, so on a real ``PassiveScanner`` backed by a
real ``SqlPersister`` (temporary SQLite file, no mocks) it must neither consume the host's
occurrence nor inflate the suppression counter, including after the state was persisted, the
session closed and a new scanner restored it: the later insecure HTTP200 must still be
reported once, and only its repeat may be counted as suppressed.
"""
import asyncio

import httpx

from wapitiCore.attack.passive_scanner import PassiveScanner
from wapitiCore.language.vulnerability import LOW_LEVEL
from wapitiCore.net import Request, Response
from wapitiCore.net.sql_persister import SqlPersister

# pylint: disable=protected-access

SAFE_URL = "http://example.test/start"
UNSAFE_URL = "http://example.test/plain"
REPEAT_URL = "http://example.test/another"
HTTPS_URL = "https://example.test/start"
CATEGORY = "Unencrypted Channels"


def safe_redirect(request: Request) -> Response:
    """Synthetic non-sensitive HTML 301 redirect to HTTPS (no socket involved)."""
    return Response(
        url=request.url,
        response=httpx.Response(
            301,
            headers={"Location": HTTPS_URL, "Content-Type": "text/html"},
            content=b"",
        ),
    )


def insecure_html(request: Request) -> Response:
    """Synthetic non-sensitive HTML 200 served in clear text."""
    return Response(
        url=request.url,
        response=httpx.Response(
            200,
            headers={"Content-Type": "text/html"},
            content=b"<html><body>ok</body></html>",
        ),
    )


async def _stored_payloads(persister: SqlPersister):
    return [payload async for payload in persister.get_payloads()]


async def _run_scenario(database) -> dict:
    """Run the crawl, restart and repeat, collecting actual persisted values."""
    counts = []
    rows = []

    # 1. Safe redirect on a fresh session: no finding, then persist and close.
    persister = SqlPersister(str(database))
    try:
        await persister.create()
        scanner = PassiveScanner(persister)
        assert "https_redirect" in scanner._modules, "https_redirect module was not loaded"
        scanner.set_modules({"https_redirect": []})

        start = Request(SAFE_URL)
        await scanner.scan(start, safe_redirect(start))
        counts.append(len(await _stored_payloads(persister)))
        await scanner.persist_state()
        state_after_safe = await persister.get_passive_scanner_state()
    finally:
        await persister.close()

    # 2. Restart on the same database, restore the state, then the real insecure responses.
    persister = SqlPersister(str(database))
    try:
        await persister.create()
        scanner = PassiveScanner(persister)
        assert "https_redirect" in scanner._modules, "https_redirect module was not loaded"
        scanner.set_modules({"https_redirect": []})
        await scanner.restore_state()

        plain = Request(UNSAFE_URL)
        await scanner.scan(plain, insecure_html(plain))
        counts.append(len(await _stored_payloads(persister)))

        another = Request(REPEAT_URL)
        await scanner.scan(another, insecure_html(another))
        counts.append(len(await _stored_payloads(persister)))

        await scanner.persist_state()
        suppressed = await persister.get_suppressed_findings()
        final_state = await persister.get_passive_scanner_state()
        rows = [
            (payload.evil_request.url, payload.level, payload.category, payload.module)
            for payload in await _stored_payloads(persister)
        ]
    finally:
        await persister.close()

    return {
        "counts": counts,
        "rows": rows,
        "suppressed": suppressed,
        "state_after_safe": state_after_safe,
        "final_state": final_state,
    }


def test_safe_redirect_does_not_consume_the_host_across_restart(tmp_path):
    outcome = asyncio.run(_run_scenario(tmp_path / "scan.db"))

    # Business assertions only: a broken gate completes the scenario but reports nothing.
    assert outcome["counts"] == [0, 1, 1]
    assert len(outcome["rows"]) == 1
    url, level, category, module = outcome["rows"][0]
    assert url == UNSAFE_URL
    assert level == LOW_LEVEL
    assert category == CATEGORY
    assert module == "https_redirect"
    assert outcome["suppressed"] == {CATEGORY: 1}

    # Recorded during the scenario: the safe redirect left the host slot untouched.
    assert outcome["state_after_safe"]["https_redirect"]["occurrences"] == []
    assert outcome["state_after_safe"]["https_redirect"]["suppressed_findings"] == 0
    assert outcome["final_state"]["https_redirect"]["occurrences"] == [["example.test", 1]]
