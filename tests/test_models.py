"""Tests for findings, check results, and exit codes."""

import pytest

from codeguard.models import CheckResult, Finding, Report, Severity, parse_severity


def _finding(severity: Severity, rule_id: str = "demo.rule") -> Finding:
    return Finding(
        check="static_analysis",
        severity=severity,
        file="src/app.py",
        line=12,
        message="example issue",
        rule_id=rule_id,
    )


def test_severity_orders_by_risk() -> None:
    assert Severity.LOW < Severity.MEDIUM < Severity.HIGH < Severity.CRITICAL
    assert Severity.CRITICAL.at_least(Severity.HIGH)
    assert not Severity.MEDIUM.at_least(Severity.HIGH)


def test_parse_severity_accepts_case_variants() -> None:
    assert parse_severity("high") is Severity.HIGH
    assert parse_severity(Severity.LOW) is Severity.LOW


def test_parse_severity_rejects_unknown_labels() -> None:
    with pytest.raises(ValueError, match="Unknown severity"):
        parse_severity("urgent")


def test_finding_rejects_line_zero() -> None:
    with pytest.raises(ValueError, match="start at 1"):
        Finding(
            check="secrets",
            severity=Severity.CRITICAL,
            file="a.env",
            line=0,
            message="bad",
            rule_id="secrets.aws",
        )


def test_finding_to_dict_uses_severity_label() -> None:
    payload = _finding(Severity.HIGH).to_dict()
    assert payload["severity"] == "HIGH"
    assert payload["file"] == "src/app.py"
    assert payload["line"] == 12


def test_high_finding_fails_default_gate() -> None:
    report = Report(
        results=[CheckResult(check="static_analysis", findings=[_finding(Severity.HIGH)])],
        fail_on=Severity.HIGH,
    )
    assert report.gate_failed()
    assert report.exit_code() == 1


def test_medium_finding_passes_when_fail_on_is_high() -> None:
    report = Report(
        results=[CheckResult(check="static_analysis", findings=[_finding(Severity.MEDIUM)])],
        fail_on=Severity.HIGH,
    )
    assert not report.gate_failed()
    assert report.exit_code() == 0


def test_failed_tests_fail_gate_even_when_fail_on_is_critical() -> None:
    report = Report(
        results=[CheckResult(check="tests", failed_tests=1)],
        fail_on=Severity.CRITICAL,
    )
    assert report.exit_code() == 1


def test_tool_error_exit_code_wins_over_gate_failure() -> None:
    report = Report(
        results=[
            CheckResult(check="tests", failed_tests=2),
            CheckResult(check="secrets", error="ruff is not installed"),
        ],
        fail_on=Severity.HIGH,
    )
    assert report.gate_failed()
    assert report.exit_code() == 2


def test_report_to_dict_includes_exit_code() -> None:
    payload = Report(results=[], fail_on="medium").to_dict()
    assert payload["fail_on"] == "MEDIUM"
    assert payload["exit_code"] == 0
    assert payload["results"] == []
