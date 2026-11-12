"""Test doubles for checker runs. Not collected by pytest."""

from __future__ import annotations

from pathlib import Path

from codeguard.checkers.base import Checker
from codeguard.config import Config
from codeguard.models import CheckResult


class StubChecker(Checker):
    """Checker that returns a canned result or raises."""

    def __init__(
        self,
        name: str,
        result: CheckResult | None = None,
        error: Exception | None = None,
    ) -> None:
        super().__init__(name)
        self._result = result if result is not None else CheckResult(check=name)
        self._error = error
        self.calls = 0

    def run(self, path: Path, config: Config) -> CheckResult:
        self.calls += 1
        if self._error is not None:
            raise self._error
        return self._result
