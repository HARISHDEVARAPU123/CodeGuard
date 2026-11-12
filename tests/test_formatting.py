"""Tests for the formatting checker."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from codeguard.checkers.formatting import (
    BLACK_INSTALL_HINT,
    MAVEN_INSTALL_HINT,
    RUFF_INSTALL_HINT,
    FormattingChecker,
    _parse_checkstyle_output,
    _parse_checkstyle_xml,
)
from codeguard.config import default_config
from codeguard.models import Severity


def test_formatting_checker_name() -> None:
    checker = FormattingChecker()
    assert checker.name == "formatting"


def test_formatting_checker_clean_repo(tmp_path: Path) -> None:
    # A temp repo with formatted python code
    py_file = tmp_path / "hello.py"
    py_file.write_text('print("hello")\n', encoding="utf-8")

    checker = FormattingChecker()
    result = checker.run(tmp_path, default_config())
    assert result.error is None
    assert result.findings == []


def test_formatting_checker_ruff_unformatted(tmp_path: Path) -> None:
    # Unformatted Python code
    py_file = tmp_path / "bad_format.py"
    py_file.write_text("x =   1\n", encoding="utf-8")

    checker = FormattingChecker()
    result = checker.run(tmp_path, default_config())
    assert result.error is None
    assert len(result.findings) >= 1
    assert result.findings[0].check == "formatting"
    assert result.findings[0].severity == Severity.LOW
    assert result.findings[0].rule_id == "format.ruff"


def test_formatting_checker_ruff_missing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("shutil.which", lambda cmd: None)
    checker = FormattingChecker()
    result = checker.run(tmp_path, default_config())
    assert result.error == RUFF_INSTALL_HINT


def test_formatting_checker_black_mode(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = default_config()
    config.python_formatter = "black"

    # Simulate black command missing
    monkeypatch.setattr(
        "shutil.which",
        lambda cmd: "black" if cmd == "black" else None,
    )

    fake_proc = subprocess.CompletedProcess(
        args=["black", "--check", "."],
        returncode=1,
        stdout="",
        stderr="would reformat app.py\n1 file would be reformatted.",
    )
    monkeypatch.setattr("subprocess.run", lambda *args, **kwargs: fake_proc)

    checker = FormattingChecker()
    result = checker.run(tmp_path, config)
    assert result.error is None
    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "format.black"
    assert result.findings[0].file == "app.py"


def test_formatting_checker_black_missing(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    config = default_config()
    config.python_formatter = "black"

    monkeypatch.setattr("shutil.which", lambda cmd: None)
    checker = FormattingChecker()
    result = checker.run(tmp_path, config)
    assert result.error == BLACK_INSTALL_HINT


def test_formatting_checker_no_pom_skips_java(tmp_path: Path) -> None:
    # No pom.xml in tmp_path -> Maven not run
    checker = FormattingChecker()
    result = checker.run(tmp_path, default_config())
    # Should not report Maven missing
    assert result.error is None or MAVEN_INSTALL_HINT not in result.error


def test_formatting_checker_pom_maven_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    (tmp_path / "pom.xml").write_text("<project></project>", encoding="utf-8")
    monkeypatch.setattr(
        "shutil.which",
        lambda cmd: "ruff" if cmd == "ruff" else None,
    )
    checker = FormattingChecker()
    result = checker.run(tmp_path, default_config())
    assert result.error is not None
    assert MAVEN_INSTALL_HINT in result.error


def test_parse_checkstyle_xml(tmp_path: Path) -> None:
    p = tmp_path.as_posix()
    xml_content = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<checkstyle version="10.0">\n'
        f'  <file name="{p}/src/Main.java">\n'
        '    <error line="15" column="5" severity="error" message="Missing Javadoc" '
        'source="com.puppycrawl.tools.checkstyle.checks.javadoc.JavadocTypeCheck"/>\n'
        "  </file>\n"
        f'  <file name="{p}/target/Generated.java">\n'
        '    <error line="1" severity="error" message="Excluded" source="checks.foo"/>\n'
        "  </file>\n"
        "</checkstyle>\n"
    )

    xml_file = tmp_path / "checkstyle-result.xml"
    xml_file.write_text(xml_content, encoding="utf-8")

    config = default_config()
    config.excludes = ["target"]
    findings = _parse_checkstyle_xml(xml_file, tmp_path, config)

    assert len(findings) == 1
    assert findings[0].file == "src/Main.java"
    assert findings[0].line == 15
    assert findings[0].rule_id == "checkstyle.JavadocTypeCheck"
    assert findings[0].severity == Severity.LOW


def test_parse_checkstyle_output(tmp_path: Path) -> None:
    output = (
        "[ERROR] src/Main.java:[10,5] (whitespace) WhitespaceAround: '{' is bad.\n"
        "[INFO] BUILD FAILURE\n"
    )
    findings = _parse_checkstyle_output(output, tmp_path, default_config())
    assert len(findings) == 1
    assert findings[0].file == "src/Main.java"
    assert findings[0].line == 10
    assert findings[0].rule_id == "checkstyle.violation"
