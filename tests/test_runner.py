"""Tests for checker selection and crash isolation."""

from pathlib import Path

import pytest

from codeguard.checkers.base import Checker
from codeguard.config import default_config
from codeguard.models import CheckResult, Finding, Severity
from codeguard.runner import RunnerError, default_checkers, run_checks
from tests.support import StubChecker


def test_checker_cannot_be_instantiated() -> None:
    with pytest.raises(TypeError):
        Checker("formatting")  # type: ignore[abstract]


def test_default_checkers_include_the_secrets_scanner() -> None:
    assert [checker.name for checker in default_checkers()] == ["secrets"]


def test_disabled_check_is_skipped(tmp_path: Path) -> None:
    config = default_config()
    config.checks["secrets"] = False
    checker = StubChecker("secrets")
    report = run_checks(tmp_path, config, [checker], only=["secrets"])
    assert checker.calls == 0
    assert report.results == []
    assert report.exit_code() == 0


def test_only_limits_which_enabled_checks_run(tmp_path: Path) -> None:
    secrets = StubChecker("secrets")
    formatting = StubChecker("formatting")
    report = run_checks(
        tmp_path,
        default_config(),
        [formatting, secrets],
        only=["secrets"],
    )
    assert formatting.calls == 0
    assert secrets.calls == 1
    assert [result.check for result in report.results] == ["secrets"]


def test_checker_crash_is_a_tool_error_and_does_not_stop_the_run(tmp_path: Path) -> None:
    broken = StubChecker("formatting", error=RuntimeError("disk full"))
    healthy = StubChecker(
        "secrets",
        result=CheckResult(
            check="secrets",
            findings=[
                Finding(
                    check="secrets",
                    severity=Severity.CRITICAL,
                    file="env",
                    line=1,
                    message="fake",
                    rule_id="secrets.aws",
                )
            ],
        ),
    )
    report = run_checks(tmp_path, default_config(), [broken, healthy])
    assert healthy.calls == 1
    assert report.results[0].error is not None
    assert "Checker crashed: RuntimeError: disk full" in report.results[0].error
    assert report.results[1].findings[0].rule_id == "secrets.aws"
    assert report.exit_code() == 2
    assert report.results[0].duration_ms >= 0


def test_finding_at_threshold_returns_exit_code_1(tmp_path: Path) -> None:
    checker = StubChecker(
        "static_analysis",
        result=CheckResult(
            check="static_analysis",
            findings=[
                Finding(
                    check="static_analysis",
                    severity=Severity.HIGH,
                    file="A.java",
                    line=4,
                    message="empty catch",
                    rule_id="java.empty-catch",
                )
            ],
        ),
    )
    report = run_checks(tmp_path, default_config(), [checker])
    assert report.exit_code() == 1


def test_missing_repository_path_raises(tmp_path: Path) -> None:
    with pytest.raises(RunnerError, match="not a directory"):
        run_checks(tmp_path / "missing", default_config(), [])


def test_unknown_only_name_raises(tmp_path: Path) -> None:
    with pytest.raises(RunnerError, match="Unknown check"):
        run_checks(tmp_path, default_config(), [], only=["lint"])
