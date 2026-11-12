"""Run test suites (pytest and Maven) and parse JUnit XML reports."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import defusedxml.ElementTree as ET
from defusedxml.common import DefusedXmlException

from codeguard.checkers.base import Checker
from codeguard.config import Config, is_excluded, to_repo_relative
from codeguard.models import CheckResult, Finding, Severity

PYTEST_INSTALL_HINT = "pytest is not installed. Install with 'pip install pytest'."
MAVEN_INSTALL_HINT = (
    "Maven (mvn) is not installed. Install Apache Maven from https://maven.apache.org "
    "and ensure 'mvn' is on PATH."
)


class TestsChecker(Checker):
    """Run Python (pytest) and Java (mvn test) test suites."""

    __test__ = False

    def __init__(self) -> None:
        super().__init__("tests")

    def run(self, path: Path, config: Config) -> CheckResult:
        """Run test suites and return counts and failure findings."""
        repo = path.resolve()
        passed_total = 0
        failed_total = 0
        skipped_total = 0
        findings: list[Finding] = []
        errors: list[str] = []

        # 1. Python tests
        if has_python_tests(repo, config.excludes):
            py_p, py_f, py_s, py_find, py_err = _run_pytest(repo, config)
            passed_total += py_p
            failed_total += py_f
            skipped_total += py_s
            findings.extend(py_find)
            if py_err:
                errors.append(py_err)

        # 2. Java tests
        pom_path = repo / "pom.xml"
        if pom_path.is_file():
            jv_p, jv_f, jv_s, jv_find, jv_err = _run_mvn_test(repo, config)
            passed_total += jv_p
            failed_total += jv_f
            skipped_total += jv_s
            findings.extend(jv_find)
            if jv_err:
                errors.append(jv_err)

        combined_error = " | ".join(errors) if errors else None
        return CheckResult(
            check=self.name,
            findings=findings,
            passed_tests=passed_total,
            failed_tests=failed_total,
            skipped_tests=skipped_total,
            error=combined_error,
        )


def has_python_tests(repo: Path, excludes: list[str]) -> bool:
    """Return True if any python test files exist outside excluded dirs."""
    tests_dir = repo / "tests"
    if tests_dir.is_dir():
        rel_tests = to_repo_relative(tests_dir, repo)
        if not is_excluded(rel_tests, excludes):
            for path in tests_dir.rglob("*.py"):
                rel_p = to_repo_relative(path, repo)
                if not is_excluded(rel_p, excludes):
                    return True

    for dirpath, dirnames, filenames in os.walk(repo):
        rel_dir = to_repo_relative(Path(dirpath), repo)
        dirnames[:] = [
            d for d in dirnames if d != ".git" and not is_excluded(f"{rel_dir}/{d}", excludes)
        ]
        for name in filenames:
            if (name.startswith("test_") or name.endswith("_test.py")) and name.endswith(".py"):
                rel_file = to_repo_relative(Path(dirpath) / name, repo)
                if not is_excluded(rel_file, excludes):
                    return True
    return False


def _run_pytest(repo: Path, config: Config) -> tuple[int, int, int, list[Finding], str | None]:
    pytest_bin = shutil.which("pytest")
    if pytest_bin is None:
        return 0, 0, 0, [], PYTEST_INSTALL_HINT

    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
        xml_path = Path(tmp.name)

    try:
        cmd = [pytest_bin, f"--junitxml={xml_path}", "-q"]
        cmd.append("--ignore=tests/fixtures")
        for excl in config.excludes:
            if excl != "tests/fixtures":
                cmd.append(f"--ignore={excl}")
        cmd.extend(config.pytest_args)

        env = os.environ.copy()
        env["PYTHONPATH"] = str(repo) + os.pathsep + env.get("PYTHONPATH", "")

        subprocess.run(
            cmd,
            cwd=repo,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=180,
            check=False,
            env=env,
        )

        if xml_path.is_file() and xml_path.stat().st_size > 0:
            try:
                p, f, s, findings = parse_junit_xml(xml_path, repo)
            except DefusedXmlException as exc:
                return 0, 0, 0, [], f"Unsafe XML in pytest report: {exc}"
            return p, f, s, findings, None
        return 0, 0, 0, [], None
    except subprocess.TimeoutExpired:
        return 0, 0, 0, [], "pytest timed out after 180 seconds."
    except OSError as exc:
        return 0, 0, 0, [], f"Failed to run pytest: {exc}"
    finally:
        if xml_path.is_file():
            try:
                xml_path.unlink()
            except OSError:
                pass


def _run_mvn_test(repo: Path, config: Config) -> tuple[int, int, int, list[Finding], str | None]:
    mvn_bin = shutil.which("mvn")
    if mvn_bin is None:
        return 0, 0, 0, [], MAVEN_INSTALL_HINT

    cmd = [mvn_bin, "test", *config.maven_args]
    try:
        subprocess.run(
            cmd,
            cwd=repo,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=300,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return 0, 0, 0, [], "mvn test timed out after 300 seconds."
    except OSError as exc:
        return 0, 0, 0, [], f"Failed to run mvn: {exc}"

    surefire_dir = repo / "target" / "surefire-reports"
    passed = 0
    failed = 0
    skipped = 0
    findings: list[Finding] = []

    if surefire_dir.is_dir():
        for report in surefire_dir.glob("TEST-*.xml"):
            try:
                p, f, s, finds = parse_junit_xml(report, repo)
            except DefusedXmlException as exc:
                return 0, 0, 0, [], f"Unsafe XML in surefire report: {exc}"
            passed += p
            failed += f
            skipped += s
            findings.extend(finds)

    return passed, failed, skipped, findings, None


def parse_junit_xml(
    xml_path: Path, repo: Path | None = None
) -> tuple[int, int, int, list[Finding]]:
    """Parse a JUnit XML report and return (passed, failed, skipped, findings)."""
    passed = 0
    failed = 0
    skipped = 0
    findings: list[Finding] = []

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except DefusedXmlException:
        # Propagate so callers can surface a tool error
        raise
    except (ET.ParseError, OSError):
        return 0, 0, 0, []

    testcases = list(root.iter("testcase"))
    for tc in testcases:
        classname = tc.attrib.get("classname", "")
        name = tc.attrib.get("name", "unknown")
        test_id = f"{classname}.{name}" if classname else name
        file_attr = tc.attrib.get("file")
        rel_file = to_repo_relative(Path(file_attr), repo) if (file_attr and repo) else file_attr

        failure = tc.find("failure")
        error = tc.find("error")
        if failure is not None or error is not None:
            failed += 1
            node = failure if failure is not None else error
            assert node is not None
            msg = node.attrib.get("message") or (node.text or "").strip() or "Test failed"
            findings.append(
                Finding(
                    check="tests",
                    severity=Severity.HIGH,
                    file=rel_file,
                    line=None,
                    message=f"Test failed: {test_id}: {msg}",
                    rule_id="test.failure",
                )
            )
        elif tc.find("skipped") is not None:
            skipped += 1
        else:
            passed += 1

    # Check for suite-level errors if no testcases failed directly
    if not testcases:
        for suite in root.iter("testsuite"):
            suite_errors = int(suite.attrib.get("errors", 0))
            suite_failures = int(suite.attrib.get("failures", 0))
            if suite_errors > 0 or suite_failures > 0:
                failed += suite_errors + suite_failures
                findings.append(
                    Finding(
                        check="tests",
                        severity=Severity.HIGH,
                        file=None,
                        line=None,
                        message=f"Test suite error in {suite.attrib.get('name', 'suite')}",
                        rule_id="test.error",
                    )
                )

    return passed, failed, skipped, findings
