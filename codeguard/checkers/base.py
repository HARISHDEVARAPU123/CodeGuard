"""Shared interface for CodeGuard checkers."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from codeguard.config import Config
from codeguard.models import CheckResult


class Checker(ABC):
    """One independently runnable quality check."""

    def __init__(self, name: str) -> None:
        self.name = name

    @abstractmethod
    def run(self, path: Path, config: Config) -> CheckResult:
        """Run the check against ``path`` and return structured results.

        Implementations should catch missing executables and return a
        ``CheckResult`` with ``error`` set, including how to install the tool.
        Unexpected exceptions are caught by the runner so one checker cannot
        abort the others.
        """
