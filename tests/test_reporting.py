"""Tests for report generation (rich console, markdown, html, json)."""

from __future__ import annotations

import json
from pathlib import Path

from rich.console import Console

from codeguard.models import CheckResult, Finding, Report, Severity
from codeguard.reporting import (
    generate_html,
    generate_json,
    generate_markdown,
    render_console,
    write_reports,
)


def sample_report() -> Report:
    return Report(
        results=[
            CheckResult(
                check="secrets",
                findings=[
                    Finding(
                        check="secrets",
                        severity=Severity.CRITICAL,
                        file="src/config.py",
                        line=12,
                        message="AWS access key detected (AKIA***).",
                        rule_id="secrets.aws-access-key",
                    )
                ],
                duration_ms=45.2,
            ),
            CheckResult(
                check="tests",
                passed_tests=10,
                failed_tests=1,
                skipped_tests=2,
                findings=[
                    Finding(
                        check="tests",
                        severity=Severity.HIGH,
                        file="tests/test_app.py",
                        line=None,
                        message="Test failed: test_foo: AssertionError",
                        rule_id="test.failure",
                    )
                ],
                duration_ms=120.5,
            ),
            CheckResult(
                check="formatting",
                error="Tool timed out",
                duration_ms=5.0,
            ),
        ],
        fail_on=Severity.HIGH,
    )


def test_render_console_empty() -> None:
    report = Report(results=[], fail_on=Severity.HIGH)
    console = Console(record=True, width=120)
    render_console(report, console=console)
    output = console.export_text()
    assert "No checks ran." in output
    assert "exit: 0" in output


def test_render_console_with_results() -> None:
    report = sample_report()
    console = Console(record=True, width=120)
    render_console(report, console=console)
    output = console.export_text()
    assert "CodeGuard Quality Gate Results" in output
    assert "secrets" in output
    assert "tests" in output
    assert "formatting" in output
    assert "exit: 2" in output  # tool error wins


def test_generate_markdown() -> None:
    report = sample_report()
    md = generate_markdown(report)
    assert "# CodeGuard Quality Gate Report" in md
    assert "**Gate Status:** ERROR" in md
    assert "| secrets | FAIL |" in md
    assert "| tests | FAIL |" in md
    assert "| formatting | ERROR |" in md
    assert "AWS access key detected (AKIA***)." in md
    assert "Test failed: test_foo: AssertionError" in md


def test_generate_html() -> None:
    report = sample_report()
    html = generate_html(report)
    assert "<!DOCTYPE html>" in html
    assert "CodeGuard Quality Gate" in html
    assert "badge-CRITICAL" in html
    assert "AKIA***" in html
    assert "Tool timed out" in html


def test_generate_json() -> None:
    report = sample_report()
    raw_json = generate_json(report)
    data = json.loads(raw_json)
    assert data["exit_code"] == 2
    assert data["fail_on"] == "HIGH"
    assert len(data["results"]) == 3
    assert data["results"][0]["check"] == "secrets"


def test_write_reports(tmp_path: Path) -> None:
    report = sample_report()
    written = write_reports(report, tmp_path, ("markdown", "html", "json"))
    assert len(written) == 3
    assert (tmp_path / "report.md").is_file()
    assert (tmp_path / "report.html").is_file()
    assert (tmp_path / "report.json").is_file()

    # Markdown file content check
    content = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert "CodeGuard Quality Gate Report" in content
