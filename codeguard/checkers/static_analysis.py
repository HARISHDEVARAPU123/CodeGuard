"""Static analysis checker: ruff + bandit for Python, line rules for Java."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from codeguard.checkers.base import Checker
from codeguard.config import Config, is_excluded, to_repo_relative
from codeguard.models import CheckResult, Finding, Severity

RUFF_INSTALL_HINT = "ruff is not installed. Install with 'pip install ruff'."
BANDIT_INSTALL_HINT = "bandit is not installed. Install with 'pip install bandit'."

_ALLOW = re.compile(r"codeguard:allow\b")
_SYSTEM_OUT = re.compile(r"\bSystem\.(?:out|err)\.(?:print|println)\b")
_STRING_EQ = re.compile(r'(?:==|!=)\s*"[^"]*"|"[^"]*"\s*(?:==|!=)')
_PRINT_STACK = re.compile(r"\.printStackTrace\s*\(")
_TODO_FIXME = re.compile(r"\b(?:TODO|FIXME)\b")
_IMPORT_STMT = re.compile(r"^\s*import\s+(?:static\s+)?([a-zA-Z0-9_.]+);")
_CATCH_START = re.compile(r"\bcatch\s*\([^)]*\)\s*\{")


class StaticAnalysisChecker(Checker):
    """Static analysis using ruff, bandit, and Java line rules."""

    def __init__(self) -> None:
        super().__init__("static_analysis")

    def run(self, path: Path, config: Config) -> CheckResult:
        """Run Python linters and Java rules across the repository."""
        repo = path.resolve()
        findings: list[Finding] = []
        errors: list[str] = []

        # 1. Python: ruff check
        ruff_findings, ruff_err = _run_ruff_check(repo, config)
        findings.extend(ruff_findings)
        if ruff_err:
            errors.append(ruff_err)

        # 2. Python: bandit
        bandit_findings, bandit_err = _run_bandit(repo, config)
        findings.extend(bandit_findings)
        if bandit_err:
            errors.append(bandit_err)

        # 3. Java: line-based rules
        java_findings = _scan_java_files(repo, config)
        findings.extend(java_findings)

        combined_error = " | ".join(errors) if errors else None
        findings.sort(key=lambda f: (f.file or "", f.line or 0, f.rule_id))
        return CheckResult(check=self.name, findings=findings, error=combined_error)


def _run_ruff_check(repo: Path, config: Config) -> tuple[list[Finding], str | None]:
    ruff = shutil.which("ruff")
    if ruff is None:
        return [], RUFF_INSTALL_HINT

    cmd = [ruff, "check", "--output-format", "json"]
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
        return [], "ruff check timed out after 60 seconds."
    except OSError as exc:
        return [], f"Failed to run ruff check: {exc}"

    findings: list[Finding] = []
    if not proc.stdout.strip():
        return findings, None

    try:
        data = json.loads(proc.stdout)
        if isinstance(data, list):
            for item in data:
                filename = item.get("filename", "")
                rel_path = to_repo_relative(Path(filename), repo)
                if is_excluded(rel_path, config.excludes):
                    continue
                code = item.get("code", "lint")
                msg = item.get("message", "Lint violation")
                row = item.get("location", {}).get("row")
                findings.append(
                    Finding(
                        check="static_analysis",
                        severity=Severity.MEDIUM,
                        file=rel_path,
                        line=row if (row and row >= 1) else None,
                        message=msg,
                        rule_id=f"ruff.{code}",
                    )
                )
    except json.JSONDecodeError:
        pass

    return findings, None


def _run_bandit(repo: Path, config: Config) -> tuple[list[Finding], str | None]:
    bandit = shutil.which("bandit")
    if bandit is None:
        return [], BANDIT_INSTALL_HINT

    # Use pyproject.toml config when available (handles skips, excludes, etc.)
    pyproject = repo / "pyproject.toml"
    if pyproject.is_file():
        cmd = [bandit, "-r", "-f", "json", "-c", "pyproject.toml"]
    else:
        # Fallback: skip assert-in-tests (B101) explicitly
        cmd = [bandit, "-r", "-f", "json", "-s", "B101"]
        if config.excludes:
            patterns: list[str] = []
            for p in config.excludes:
                patterns.append(p)
                patterns.append(p.replace("/", os.sep))
            cmd.extend(["-x", ",".join(patterns)])
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
        return [], "bandit timed out after 60 seconds."
    except OSError as exc:
        return [], f"Failed to run bandit: {exc}"

    findings: list[Finding] = []
    if not proc.stdout.strip():
        return findings, None

    try:
        data = json.loads(proc.stdout)
        results = data.get("results", [])
        for item in results:
            filename = item.get("filename", "")
            rel_path = to_repo_relative(Path(filename), repo)
            if is_excluded(rel_path, config.excludes):
                continue
            line = item.get("line_number")
            raw_sev = str(item.get("issue_severity", "MEDIUM")).upper()
            try:
                sev = Severity(raw_sev)
            except ValueError:
                sev = Severity.MEDIUM
            test_id = item.get("test_id", "issue")
            msg = item.get("issue_text", "Security issue detected")
            findings.append(
                Finding(
                    check="static_analysis",
                    severity=sev,
                    file=rel_path,
                    line=line if (line and line >= 1) else None,
                    message=msg,
                    rule_id=f"bandit.{test_id}",
                )
            )
    except json.JSONDecodeError:
        pass

    return findings, None


def _scan_java_files(repo: Path, config: Config) -> list[Finding]:
    findings: list[Finding] = []
    for dirpath, dirnames, filenames in os.walk(repo):
        rel_dir = to_repo_relative(Path(dirpath), repo)
        dirnames[:] = [
            d
            for d in dirnames
            if d != ".git" and not is_excluded(f"{rel_dir}/{d}", config.excludes)
        ]
        for name in filenames:
            if not name.endswith(".java"):
                continue
            full_path = Path(dirpath) / name
            rel_path = to_repo_relative(full_path, repo)
            if is_excluded(rel_path, config.excludes):
                continue
            findings.extend(
                scan_java_source(rel_path, full_path.read_text(encoding="utf-8", errors="replace"))
            )
    return findings


def scan_java_source(rel_path: str, content: str) -> list[Finding]:
    """Scan a single Java file's text for anti-pattern line rules."""
    findings: list[Finding] = []
    lines = content.splitlines()

    # Track imports for unused imports check
    imports: list[tuple[str, int]] = []
    body_lines: list[str] = []

    for idx, line in enumerate(lines, start=1):
        if _ALLOW.search(line):
            continue

        match_import = _IMPORT_STMT.match(line)
        if match_import:
            full_import = match_import.group(1)
            symbol = full_import.split(".")[-1]
            if symbol != "*":
                imports.append((symbol, idx))
            continue

        body_lines.append(line)

        # 1. System.out / System.err
        if _SYSTEM_OUT.search(line):
            findings.append(
                Finding(
                    check="static_analysis",
                    severity=Severity.MEDIUM,
                    file=rel_path,
                    line=idx,
                    message="Direct call to System.out/err. Use a logger instead.",
                    rule_id="java.system-out",
                )
            )

        # 2. String comparison using == or !=
        if _STRING_EQ.search(line):
            findings.append(
                Finding(
                    check="static_analysis",
                    severity=Severity.HIGH,
                    file=rel_path,
                    line=idx,
                    message="String literal comparison using == or !=. Use .equals() instead.",
                    rule_id="java.string-compare-eq",
                )
            )

        # 3. printStackTrace()
        if _PRINT_STACK.search(line):
            findings.append(
                Finding(
                    check="static_analysis",
                    severity=Severity.MEDIUM,
                    file=rel_path,
                    line=idx,
                    message="Call to printStackTrace(). Use a logger instead.",
                    rule_id="java.print-stack-trace",
                )
            )

        # 4. TODO / FIXME
        if _TODO_FIXME.search(line):
            findings.append(
                Finding(
                    check="static_analysis",
                    severity=Severity.LOW,
                    file=rel_path,
                    line=idx,
                    message="TODO/FIXME comment found.",
                    rule_id="java.todo-fixme",
                )
            )

    # 5. Empty catch blocks (single-line or multi-line)
    findings.extend(_find_empty_catches(rel_path, lines))

    # 6. Unused imports
    body_text = "\n".join(body_lines)
    for symbol, line_num in imports:
        # Check if symbol appears as a distinct word in the body text
        pattern = rf"\b{re.escape(symbol)}\b"
        if not re.search(pattern, body_text):
            findings.append(
                Finding(
                    check="static_analysis",
                    severity=Severity.LOW,
                    file=rel_path,
                    line=line_num,
                    message=f"Unused import '{symbol}'.",
                    rule_id="java.unused-import",
                )
            )

    return findings


def _find_empty_catches(rel_path: str, lines: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    i = 0
    total = len(lines)
    while i < total:
        line = lines[i]
        if _ALLOW.search(line):
            i += 1
            continue

        match = _CATCH_START.search(line)
        if match:
            catch_line = i + 1
            after_brace = line[match.end() :]
            if "}" in after_brace:
                # Same line catch block
                inside = after_brace[: after_brace.index("}")].strip()
                if not inside or inside.startswith("//") or inside.startswith("/*"):
                    findings.append(
                        Finding(
                            check="static_analysis",
                            severity=Severity.HIGH,
                            file=rel_path,
                            line=catch_line,
                            message="Empty catch block detected.",
                            rule_id="java.empty-catch",
                        )
                    )
            else:
                # Multi-line catch block: scan forward
                j = i + 1
                empty = True
                while j < total:
                    next_line = lines[j]
                    if _ALLOW.search(next_line):
                        empty = False
                        break
                    stripped = next_line.strip()
                    if stripped == "}":
                        break
                    if "}" in stripped:
                        before = stripped[: stripped.index("}")].strip()
                        if before and not before.startswith("//") and not before.startswith("/*"):
                            empty = False
                        break
                    if stripped and not stripped.startswith("//") and not stripped.startswith("/*"):
                        empty = False
                        break
                    j += 1
                if empty and j < total:
                    findings.append(
                        Finding(
                            check="static_analysis",
                            severity=Severity.HIGH,
                            file=rel_path,
                            line=catch_line,
                            message="Empty catch block detected.",
                            rule_id="java.empty-catch",
                        )
                    )
        i += 1
    return findings
