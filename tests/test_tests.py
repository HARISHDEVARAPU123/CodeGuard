"""Tests for the test runner checker (pytest and Maven)."""

from __future__ import annotations

from pathlib import Path

import pytest

from codeguard.checkers.tests import (
    MAVEN_INSTALL_HINT,
    PYTEST_INSTALL_HINT,
    TestsChecker,
    has_python_tests,
    parse_junit_xml,
)
from codeguard.config import default_config
from codeguard.models import Severity


def test_tests_checker_name() -> None:
    checker = TestsChecker()
    assert checker.name == "tests"


def test_parse_junit_xml_mixed(tmp_path: Path) -> None:
    xml_content = """<?xml version="1.0" encoding="utf-8"?>
<testsuites>
  <testsuite name="pytest" errors="0" failures="1" skipped="1" tests="3">
    <testcase classname="test_app" name="test_ok" file="test_app.py" time="0.01"/>
    <testcase classname="test_app" name="test_fail" file="test_app.py" time="0.02">
      <failure message="AssertionError: 1 != 2">def test_fail(): assert 1 == 2</failure>
    </testcase>
    <testcase classname="test_app" name="test_skip" file="test_app.py" time="0.00">
      <skipped type="pytest.skip" message="unsupported"/>
    </testcase>
  </testsuite>
</testsuites>
"""
    xml_file = tmp_path / "report.xml"
    xml_file.write_text(xml_content, encoding="utf-8")

    passed, failed, skipped, findings = parse_junit_xml(xml_file, tmp_path)
    assert passed == 1
    assert failed == 1
    assert skipped == 1
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].rule_id == "test.failure"
    assert "test_app.test_fail" in findings[0].message
    assert "1 != 2" in findings[0].message


def test_parse_junit_xml_suite_error(tmp_path: Path) -> None:
    xml_content = """<?xml version="1.0" encoding="utf-8"?>
<testsuite name="suite_crash" errors="1" failures="0" skipped="0" tests="0">
</testsuite>
"""
    xml_file = tmp_path / "crash.xml"
    xml_file.write_text(xml_content, encoding="utf-8")

    passed, failed, skipped, findings = parse_junit_xml(xml_file, tmp_path)
    assert passed == 0
    assert failed == 1
    assert len(findings) == 1
    assert findings[0].rule_id == "test.error"


def test_has_python_tests_false(tmp_path: Path) -> None:
    assert not has_python_tests(tmp_path, [])
    (tmp_path / "app.py").write_text("print(1)\n", encoding="utf-8")
    assert not has_python_tests(tmp_path, [])


def test_has_python_tests_true(tmp_path: Path) -> None:
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_sample.py").write_text("def test_ok(): pass\n", encoding="utf-8")
    assert has_python_tests(tmp_path, [])


def test_tests_checker_no_tests_and_no_pom(tmp_path: Path) -> None:
    checker = TestsChecker()
    result = checker.run(tmp_path, default_config())
    assert result.error is None
    assert result.passed_tests == 0
    assert result.failed_tests == 0
    assert result.skipped_tests == 0
    assert result.findings == []


def test_tests_checker_pom_missing_maven(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    (tmp_path / "pom.xml").write_text("<project></project>", encoding="utf-8")
    monkeypatch.setattr("shutil.which", lambda cmd: None)

    checker = TestsChecker()
    result = checker.run(tmp_path, default_config())
    assert result.error is not None
    assert MAVEN_INSTALL_HINT in result.error


def test_tests_checker_pytest_missing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_a.py").write_text("def test_x(): pass\n", encoding="utf-8")

    monkeypatch.setattr("shutil.which", lambda cmd: None)
    checker = TestsChecker()
    result = checker.run(tmp_path, default_config())
    assert result.error is not None
    assert PYTEST_INSTALL_HINT in result.error


def test_tests_checker_runs_pytest_on_real_tests(tmp_path: Path) -> None:
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_one.py").write_text(
        "def test_pass(): assert True\ndef test_fail(): assert False\n",
        encoding="utf-8",
    )

    checker = TestsChecker()
    result = checker.run(tmp_path, default_config())
    assert result.error is None
    assert result.passed_tests == 1
    assert result.failed_tests == 1
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.HIGH
    assert "test_fail" in result.findings[0].message
