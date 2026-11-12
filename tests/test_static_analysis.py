"""Tests for static analysis (ruff check, bandit, Java line rules)."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from codeguard.checkers.static_analysis import (
    BANDIT_INSTALL_HINT,
    RUFF_INSTALL_HINT,
    StaticAnalysisChecker,
    scan_java_source,
)
from codeguard.config import default_config
from codeguard.models import Severity


def test_static_analysis_checker_name() -> None:
    checker = StaticAnalysisChecker()
    assert checker.name == "static_analysis"


def test_java_rules_empty_catch() -> None:
    code_single = (
        "public class Test {\n"
        "    public void run() {\n"
        "        try { work(); } catch (Exception e) {}\n"
        "    }\n"
        "}\n"
    )
    findings = scan_java_source("Test.java", code_single)
    rule_ids = [f.rule_id for f in findings]
    assert "java.empty-catch" in rule_ids
    empty_finding = next(f for f in findings if f.rule_id == "java.empty-catch")
    assert empty_finding.severity == Severity.HIGH
    assert empty_finding.line == 3

    code_multi = (
        "public class Test {\n"
        "    public void run() {\n"
        "        try {\n"
        "            work();\n"
        "        } catch (IOException e) {\n"
        "            // ignored\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    findings_multi = scan_java_source("Test.java", code_multi)
    assert any(f.rule_id == "java.empty-catch" for f in findings_multi)

    code_non_empty = (
        "public class Test {\n"
        "    public void run() {\n"
        "        try { work(); } catch (Exception e) {\n"
        "            logger.error(e);\n"
        "        }\n"
        "    }\n"
        "}\n"
    )
    findings_non_empty = scan_java_source("Test.java", code_non_empty)
    assert not any(f.rule_id == "java.empty-catch" for f in findings_non_empty)


def test_java_rules_system_out_and_stack_trace() -> None:
    code = (
        "public class Test {\n"
        "    public void run() {\n"
        '        System.out.println("Hello");\n'
        "        e.printStackTrace();\n"
        "    }\n"
        "}\n"
    )
    findings = scan_java_source("Test.java", code)
    rule_ids = {f.rule_id for f in findings}
    assert "java.system-out" in rule_ids
    assert "java.print-stack-trace" in rule_ids


def test_java_rules_string_eq() -> None:
    code = (
        "public class Test {\n"
        "    public boolean check(String s) {\n"
        '        if (s == "admin") return true;\n'
        '        if ("guest" != s) return false;\n'
        "        return false;\n"
        "    }\n"
        "}\n"
    )
    findings = scan_java_source("Test.java", code)
    eq_findings = [f for f in findings if f.rule_id == "java.string-compare-eq"]
    assert len(eq_findings) == 2
    assert eq_findings[0].severity == Severity.HIGH


def test_java_rules_unused_imports_and_todo() -> None:
    code = (
        "package com.example;\n"
        "import java.util.List;\n"
        "import java.util.Map;\n"
        "import java.util.*;\n"
        "public class Test {\n"
        "    // TODO: implement this\n"
        "    private Map<String, String> data;\n"
        "}\n"
    )
    findings = scan_java_source("Test.java", code)
    rule_ids = [f.rule_id for f in findings]
    assert "java.todo-fixme" in rule_ids
    assert "java.unused-import" in rule_ids
    unused = next(f for f in findings if f.rule_id == "java.unused-import")
    assert unused.line == 2
    assert "List" in unused.message


def test_java_rules_allow_comment() -> None:
    code = (
        "public class Test {\n"
        "    public void run() {\n"
        '        System.out.println("allowed"); // codeguard:allow\n'
        "    }\n"
        "}\n"
    )
    findings = scan_java_source("Test.java", code)
    assert findings == []


def test_ruff_check_missing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        "shutil.which",
        lambda cmd: "bandit" if cmd == "bandit" else None,
    )
    checker = StaticAnalysisChecker()
    result = checker.run(tmp_path, default_config())
    assert result.error is not None
    assert RUFF_INSTALL_HINT in result.error


def test_bandit_missing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(
        "shutil.which",
        lambda cmd: "ruff" if cmd == "ruff" else None,
    )
    checker = StaticAnalysisChecker()
    result = checker.run(tmp_path, default_config())
    assert result.error is not None
    assert BANDIT_INSTALL_HINT in result.error


def test_bandit_findings(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("shutil.which", lambda cmd: cmd)

    fake_proc = subprocess.CompletedProcess(
        args=["bandit", "-r", "-f", "json", "."],
        returncode=1,
        stdout=(
            '{"results": [{"filename": "app.py", "line_number": 5, '
            '"issue_severity": "HIGH", "issue_text": "Shell injection", "test_id": "B602"}]}'
        ),
        stderr="",
    )

    def fake_run(
        cmd: list[str], *args: object, **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        if "bandit" in cmd[0]:
            return fake_proc
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="[]", stderr="")

    monkeypatch.setattr("subprocess.run", fake_run)

    checker = StaticAnalysisChecker()
    result = checker.run(tmp_path, default_config())
    assert result.error is None
    bandit_findings = [f for f in result.findings if f.rule_id == "bandit.B602"]
    assert len(bandit_findings) == 1
    assert bandit_findings[0].severity == Severity.HIGH
    assert bandit_findings[0].file == "app.py"
