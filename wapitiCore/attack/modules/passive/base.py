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

    def __init__(self):
        self._occurrences: dict = defaultdict(int)
        # Number of alerts dropped because their key already reached LIMIT.
        self.suppressed_findings: int = 0

    def should_report(self, key: Any) -> bool:
        """Return True for the first :attr:`LIMIT` occurrences of a key, then False.

        A single decision drives both logging and persistence: when it returns
        False the caller must emit nothing (no log line, no finding) — the alert
        is only counted as suppressed. This guarantees logs and report never
        diverge.
        """
        if self._occurrences[key] >= self.LIMIT:
            self.suppressed_findings += 1
            return False

        self._occurrences[key] += 1
        return True

    def analyze(self, request: Request, response: Response) -> Generator[VulnerabilityInstance, Any, None]:
        raise NotImplementedError
