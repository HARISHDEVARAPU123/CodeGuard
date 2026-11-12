"""Check code formatting using ruff/black for Python and checkstyle for Java."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import defusedxml.ElementTree as ET
from defusedxml.common import DefusedXmlException

from codeguard.checkers.base import Checker
from codeguard.config import Config, is_excluded, to_repo_relative
from codeguard.models import CheckResult, Finding, Severity

RUFF_INSTALL_HINT = "ruff is not installed. Install with 'pip install ruff'."
BLACK_INSTALL_HINT = "black is not installed. Install with 'pip install black'."
MAVEN_INSTALL_HINT = (
    "Maven (mvn) is not installed. Install Apache Maven from https://maven.apache.org "
    "and ensure 'mvn' is on PATH."
)

_BLACK_REFORMAT = re.compile(r"^would reformat (.+)$", re.MULTILINE)
_CHECKSTYLE_LINE = re.compile(r"^\[(?:ERROR|WARN)\]\s*(.+?):\[(\d+),\d+\]\s*(.+)$", re.MULTILINE)


class FormattingChecker(Checker):
    """Run code format checks on Python and Java files."""

    def __init__(self) -> None:
        super().__init__("formatting")

    def run(self, path: Path, config: Config) -> CheckResult:
        """Run configured formatters and return findings."""
        repo = path.resolve()
        findings: list[Finding] = []
        errors: list[str] = []

        # 1. Python formatting
        py_findings, py_error = self._check_python(repo, config)
        findings.extend(py_findings)
        if py_error:
            errors.append(py_error)

        # 2. Java formatting (when pom.xml exists)
        pom_path = repo / "pom.xml"
        if pom_path.is_file():
            java_findings, java_error = self._check_java(repo, config)
            findings.extend(java_findings)
            if java_error:
                errors.append(java_error)

        combined_error = " | ".join(errors) if errors else None
        return CheckResult(check=self.name, findings=findings, error=combined_error)

    def _check_python(self, repo: Path, config: Config) -> tuple[list[Finding], str | None]:
        formatter = config.python_formatter
        if formatter == "black":
            return _run_black(repo, config)
        return _run_ruff(repo, config)

    def _check_java(self, repo: Path, config: Config) -> tuple[list[Finding], str | None]:
        mvn = shutil.which("mvn")
        if mvn is None:
            return [], MAVEN_INSTALL_HINT

        cmd = [mvn, "-q", "checkstyle:check", *config.maven_args]
        try:
            proc = subprocess.run(
                cmd,
                cwd=repo,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=120,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return [], "Maven checkstyle timed out after 120 seconds."
        except OSError as exc:
            return [], f"Failed to run Maven: {exc}"

        findings: list[Finding] = []
        # Check XML report first
        xml_path = repo / "target" / "checkstyle-result.xml"
        if xml_path.is_file():
            try:
                findings = _parse_checkstyle_xml(xml_path, repo, config)
            except (DefusedXmlException, ET.ParseError) as exc:
                return [], f"Invalid Checkstyle XML report: {exc}"
        elif proc.returncode != 0:
            findings = _parse_checkstyle_output(proc.stdout + "\n" + proc.stderr, repo, config)

        return findings, None


def _run_ruff(repo: Path, config: Config) -> tuple[list[Finding], str | None]:
    ruff = shutil.which("ruff")
    if ruff is None:
        return [], RUFF_INSTALL_HINT

    cmd = [ruff, "format", "--check", "--output-format", "json"]
    for pattern in config.excludes:
        cmd.extend(["--extend-exclude", pattern])
    cmd.append(".")

    try:
        proc = subprocess.run(
            cmd,
            cwd=repo,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return [], "ruff format timed out after 60 seconds."
    except OSError as exc:
        return [], f"Failed to run ruff: {exc}"

    findings: list[Finding] = []
    if proc.returncode == 0:
        return findings, None

    # Parse JSON output
    try:
        data = json.loads(proc.stdout)
        if isinstance(data, list):
            for item in data:
                filename = item.get("filename", "")
                rel_path = to_repo_relative(Path(filename), repo)
                if is_excluded(rel_path, config.excludes):
                    continue
                row = item.get("location", {}).get("row")
                findings.append(
                    Finding(
                        check="formatting",
                        severity=Severity.LOW,
                        file=rel_path,
                        line=row if (row and row >= 1) else None,
                        message=item.get("message", "File would be reformatted"),
                        rule_id="format.ruff",
                    )
                )
            return findings, None
    except json.JSONDecodeError:
        pass

    # Fallback text parsing if JSON parsing didn't work
    for line in (proc.stdout + "\n" + proc.stderr).splitlines():
        if "would be reformatted" in line:
            parts = line.split(":", 1)
            file_part = parts[0].strip() if len(parts) > 1 else None
            rel_file = to_repo_relative(Path(file_part), repo) if file_part else None
            findings.append(
                Finding(
                    check="formatting",
                    severity=Severity.LOW,
                    file=rel_file,
                    line=None,
                    message="File would be reformatted",
                    rule_id="format.ruff",
                )
            )

    return findings, None


def _run_black(repo: Path, config: Config) -> tuple[list[Finding], str | None]:
    black = shutil.which("black")
    if black is None:
        return [], BLACK_INSTALL_HINT

    cmd = [black, "--check", "."]
    try:
        proc = subprocess.run(
            cmd,
            cwd=repo,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return [], "black timed out after 60 seconds."
    except OSError as exc:
        return [], f"Failed to run black: {exc}"

    findings: list[Finding] = []
    if proc.returncode == 0:
        return findings, None

    for match in _BLACK_REFORMAT.finditer(proc.stderr):
        raw_file = match.group(1).strip()
        rel_path = to_repo_relative(Path(raw_file), repo)
        if is_excluded(rel_path, config.excludes):
            continue
        findings.append(
            Finding(
                check="formatting",
                severity=Severity.LOW,
                file=rel_path,
                line=None,
                message="File would be reformatted",
                rule_id="format.black",
            )
        )

    return findings, None


def _parse_checkstyle_xml(xml_path: Path, repo: Path, config: Config) -> list[Finding]:
    findings: list[Finding] = []
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except OSError:
        return findings

    for file_elem in root.findall("file"):
        file_name = file_elem.attrib.get("name", "")
        rel_path = to_repo_relative(Path(file_name), repo)
        if is_excluded(rel_path, config.excludes):
            continue

        for error in file_elem.findall("error"):
            line_str = error.attrib.get("line")
            line = int(line_str) if line_str and line_str.isdigit() and int(line_str) >= 1 else None
            msg = error.attrib.get("message", "Checkstyle violation")
            source = error.attrib.get("source", "violation")
            rule_id = f"checkstyle.{source.split('.')[-1]}"
            findings.append(
                Finding(
                    check="formatting",
                    severity=Severity.LOW,
                    file=rel_path,
                    line=line,
                    message=msg,
                    rule_id=rule_id,
                )
            )
    return findings


def _parse_checkstyle_output(output: str, repo: Path, config: Config) -> list[Finding]:
    findings: list[Finding] = []
    for match in _CHECKSTYLE_LINE.finditer(output):
        raw_file, line_str, msg = match.groups()
        rel_path = to_repo_relative(Path(raw_file), repo)
        if is_excluded(rel_path, config.excludes):
            continue
        line = int(line_str) if line_str.isdigit() and int(line_str) >= 1 else None
        findings.append(
            Finding(
                check="formatting",
                severity=Severity.LOW,
                file=rel_path,
                line=line,
                message=msg.strip(),
                rule_id="checkstyle.violation",
            )
        )
    return findings
