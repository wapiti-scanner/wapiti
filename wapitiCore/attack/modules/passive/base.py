# This file is part of the Wapiti project (https://wapiti-scanner.github.io)
# Copyright (C) 2026 Nicolas Surribas
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
from collections import defaultdict
from typing import Any, Generator

from wapitiCore.model.vulnerability import VulnerabilityInstance
from wapitiCore.net import Request, Response


class PassiveModule:
    """Base class shared by every passive module.

    It centralizes the anti-flood logic that used to be copy-pasted in each
    module: a per-key occurrence cap (:attr:`LIMIT`) and a counter of the alerts
    that were suppressed once that cap was reached. Historically each module kept
    its own ``set`` of already reported identifiers, which is exactly this model
    with ``LIMIT = 1``.
    """

    name: str = ""
    # Maximum number of alerts reported per deduplication key. The default of 1
    # reproduces the historical "report once per key" behavior.
    LIMIT: int = 1
    # Whether the module is also run on the responses produced by active attack modules.
    # Only modules analysing the response body benefit from it (a payload may trigger an
    # error page); header / redirect / form based modules would only add noise.
    scan_attack_responses: bool = False

    def __init__(self):
        self._occurrences: dict = defaultdict(int)
        # Number of alerts dropped because their key already reached LIMIT.
        self.suppressed_findings: int = 0
        # Same count, but broken down per vulnerability category (finding class
        # name) so the report can annotate the right summary line and section.
        self.suppressed_by_category: dict = defaultdict(int)

    def should_report(self, key: Any, finding_class=None) -> bool:
        """Return True for the first :attr:`LIMIT` occurrences of a key, then False.

        A single decision drives both logging and persistence: when it returns
        False the caller must emit nothing (no log line, no finding) — the alert
        is only counted as suppressed. This guarantees logs and report never
        diverge.

        ``finding_class`` is the vulnerability class the caller would have
        emitted; when provided, suppressions are also tallied per category
        (``finding_class.name()``) so the report can surface them where the
        matching findings live.
        """
        if self._occurrences[key] >= self.LIMIT:
            self.suppressed_findings += 1
            if finding_class is not None:
                self.suppressed_by_category[finding_class.name()] += 1
            return False

        self._occurrences[key] += 1
        return True

    def get_state(self) -> dict:
        """Serializable snapshot of the anti-flood state.

        A resumed crawl (``--resume-crawl``) re-instantiates every module with an
        empty state. Without restoring this snapshot the module would treat keys it
        already capped during the interrupted run as unseen and re-emit duplicate
        alerts, while the suppression counters would restart from zero.

        Deduplication keys are frequently tuples (e.g. ``(host, header, ...)``),
        which JSON cannot use as object keys. Occurrences are therefore stored as a
        list of ``[key, count]`` pairs — a tuple key becomes a JSON array and is
        turned back into a tuple in :meth:`load_state`.
        """
        return {
            "occurrences": [[key, count] for key, count in self._occurrences.items()],
            "suppressed_findings": self.suppressed_findings,
            "suppressed_by_category": dict(self.suppressed_by_category),
        }

    def load_state(self, state: dict) -> None:
        """Restore a snapshot previously produced by :meth:`get_state`."""
        occurrences: dict = defaultdict(int)
        for key, count in state.get("occurrences", []):
            # JSON has no tuple type: composite keys come back as lists and must be
            # turned back into (hashable) tuples to match the keys modules generate.
            occurrences[tuple(key) if isinstance(key, list) else key] = count
        self._occurrences = occurrences
        self.suppressed_findings = state.get("suppressed_findings", 0)
        self.suppressed_by_category = defaultdict(int, state.get("suppressed_by_category", {}))

    def analyze(self, request: Request, response: Response) -> Generator[VulnerabilityInstance, Any, None]:
        raise NotImplementedError
