"""Tests for the command-line skeleton."""

from pathlib import Path

import pytest

from codeguard.cli import format_summary, main, parse_formats, parse_only
from codeguard.models import CheckResult, Finding, Report, Severity
from tests.support import StubChecker


def test_parse_formats_expands_all() -> None:
    assert parse_formats("all") == ("console", "markdown", "html", "json")
    assert parse_formats("json,console,json") == ("json", "console")


def test_parse_formats_rejects_unknown_names() -> None:
    with pytest.raises(ValueError, match="Unknown format"):
        parse_formats("pdf")


def test_parse_only_rejects_unknown_checks() -> None:
    assert parse_only("secrets,tests") == ("secrets", "tests")
    assert parse_only(None) is None
    with pytest.raises(ValueError, match="Unknown check"):
        parse_only("secrets,style")


def test_run_with_no_checkers_passes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["run", "--path", str(tmp_path)], checkers=[])
    captured = capsys.readouterr()
    assert code == 0
    assert "No checks ran." in captured.out
    assert "exit: 0" in captured.out
    assert captured.err == ""


def test_explicit_missing_config_is_exit_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(
        ["run", "--path", str(tmp_path), "--config", str(tmp_path / "missing.yml")],
        checkers=[],
    )
    captured = capsys.readouterr()
    assert code == 2
    assert "not found" in captured.err


def test_fail_on_and_only_flags(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    config = tmp_path / "codeguard.yml"
    config.write_text("fail_on: CRITICAL\n", encoding="utf-8")
    checker = StubChecker(
        "secrets",
        result=CheckResult(
            check="secrets",
            findings=[
                Finding(
                    check="secrets",
                    severity=Severity.MEDIUM,
                    file="app.py",
                    line=3,
                    message="example",
                    rule_id="secrets.generic",
                )
            ],
        ),
    )
    other = StubChecker("formatting")
    code = main(
        [
            "run",
            "--path",
            str(tmp_path),
            "--config",
            str(config),
            "--fail-on",
            "MEDIUM",
            "--only",
            "secrets,formatting",
        ],
        checkers=[checker, other],
    )
    captured = capsys.readouterr()
    assert code == 1
    assert checker.calls == 1
    assert other.calls == 1
    assert "secrets: FAIL" in captured.out
    assert "[MEDIUM] secrets.generic app.py:3 example" in captured.out


def test_only_skips_checks_that_were_not_named(tmp_path: Path) -> None:
    secrets = StubChecker("secrets")
    tests = StubChecker("tests")
    code = main(
        ["run", "--path", str(tmp_path), "--only", "tests"],
        checkers=[secrets, tests],
    )
    assert code == 0
    assert secrets.calls == 0
    assert tests.calls == 1


def test_file_formats_are_written(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["run", "--path", str(tmp_path), "--format", "all"], checkers=[])
    assert code == 0
    assert (tmp_path / "report.md").is_file()
    assert (tmp_path / "report.html").is_file()
    assert (tmp_path / "report.json").is_file()


def test_bad_only_flag_is_exit_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["run", "--path", str(tmp_path), "--only", "nope"], checkers=[])
    assert code == 2
    assert "Unknown check" in capsys.readouterr().err


def test_version_flag() -> None:
    with pytest.raises(SystemExit) as caught:
        main(["--version"])
    assert caught.value.code == 0


def test_format_summary_lists_test_counts() -> None:
    text = format_summary(
        Report(
            results=[CheckResult(check="tests", passed_tests=3, failed_tests=1, skipped_tests=2)],
            fail_on=Severity.HIGH,
        )
    )
    assert "tests: FAIL" in text
    assert "tests=3 passed, 1 failed, 2 skipped" in text
    assert text.endswith("exit: 1")
