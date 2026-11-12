"""Run enabled checkers and turn their results into an exit code."""

from __future__ import annotations

import time
from collections.abc import Sequence
from pathlib import Path

from codeguard.checkers.base import Checker
from codeguard.checkers.secrets import SecretsChecker
from codeguard.config import Config
from codeguard.models import CHECK_NAMES, CheckResult, Report


class RunnerError(Exception):
    """The run could not start because the repository path is unusable."""


def default_checkers() -> list[Checker]:
    """Return the built-in checkers that are implemented so far."""
    return [SecretsChecker()]


def run_checks(
    path: Path,
    config: Config,
    checkers: Sequence[Checker],
    only: Sequence[str] | None = None,
) -> Report:
    """Run each selected checker and aggregate a report.

    ``only`` narrows the checks that are already enabled in ``config``.
    A checker that raises is recorded as a tool error. Later checkers still run.
    """
    repo = path.resolve()
    if not repo.is_dir():
        raise RunnerError(f"Repository path is not a directory: {path}")

    selected = _select_names(only)
    results: list[CheckResult] = []
    for checker in checkers:
        if checker.name not in selected or not config.check_enabled(checker.name):
            continue
        results.append(_invoke(checker, repo, config))
    return Report(results=results, fail_on=config.fail_on)


def _select_names(only: Sequence[str] | None) -> frozenset[str]:
    if only is None:
        return frozenset(CHECK_NAMES)
    unknown = [name for name in only if name not in CHECK_NAMES]
    if unknown:
        known = ", ".join(CHECK_NAMES)
        raise RunnerError(f"Unknown check names: {', '.join(unknown)}. Expected one of: {known}.")
    return frozenset(only)


def _invoke(checker: Checker, repo: Path, config: Config) -> CheckResult:
    started = time.perf_counter()
    try:
        result = checker.run(repo, config)
    except Exception as exc:
        result = CheckResult(
            check=checker.name,
            error=f"Checker crashed: {exc.__class__.__name__}: {exc}",
        )
    result.check = checker.name
    result.duration_ms = (time.perf_counter() - started) * 1000
    return result
