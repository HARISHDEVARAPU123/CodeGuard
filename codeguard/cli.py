"""Command-line entry point for CodeGuard."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from codeguard import __version__
from codeguard.checkers.base import Checker
from codeguard.config import ConfigError, resolve_config
from codeguard.models import CHECK_NAMES, CheckResult, Finding, Report, Severity, parse_severity
from codeguard.reporting import render_console, write_reports
from codeguard.runner import RunnerError, default_checkers, run_checks

FORMAT_NAMES: tuple[str, ...] = ("console", "markdown", "html", "json", "all")
_FILE_FORMATS = ("markdown", "html", "json")


def build_parser() -> argparse.ArgumentParser:
    """Return the argument parser used by ``codeguard``."""
    parser = argparse.ArgumentParser(
        prog="codeguard",
        description="Run pre-merge quality checks and fail CI when the gate does not pass.",
        epilog=(
            "examples:\n"
            "  codeguard run --path . --config codeguard.yml --format all\n"
            "  codeguard run --fail-on MEDIUM --only secrets,tests"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"codeguard {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Run enabled checks against a repository.")
    run_parser.add_argument(
        "--path",
        default=".",
        type=Path,
        help="Repository root to scan. Defaults to the current directory.",
    )
    run_parser.add_argument(
        "--config",
        default=None,
        type=Path,
        help="Path to codeguard.yml. Defaults to <path>/codeguard.yml when that file exists.",
    )
    run_parser.add_argument(
        "--format",
        default="console",
        help="Report format: console, markdown, html, json, or all. Default: console.",
    )
    run_parser.add_argument(
        "--fail-on",
        default=None,
        choices=[level.value for level in Severity],
        help="Minimum finding severity that fails the gate. Overrides the config file.",
    )
    run_parser.add_argument(
        "--only",
        default=None,
        help="Comma-separated checks to run: " + ", ".join(CHECK_NAMES) + ".",
    )
    return parser


def main(
    argv: Sequence[str] | None = None,
    checkers: Sequence[Checker] | None = None,
) -> int:
    """Parse arguments, run checks, print a text summary, and return an exit code.

    ``checkers`` is a test seam. The CLI uses ``default_checkers()`` when it is omitted.
    File reports (markdown, HTML, JSON) are parsed now and written in a later phase.
    """
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.command != "run":
        parser.error(f"Unknown command {args.command!r}.")

    try:
        formats = parse_formats(args.format)
        only = parse_only(args.only)
        repo = args.path
        config = resolve_config(repo, args.config)
        if args.fail_on is not None:
            config.fail_on = parse_severity(args.fail_on)
        report = run_checks(
            repo,
            config,
            default_checkers() if checkers is None else list(checkers),
            only=only,
        )
    except (ConfigError, RunnerError, ValueError) as exc:
        print(f"codeguard: {exc}", file=sys.stderr)
        return 2

    if "console" in formats:
        render_console(report)
    write_reports(report, repo, formats)
    return report.exit_code()


def parse_formats(value: str) -> tuple[str, ...]:
    """Parse ``--format`` into concrete report names.

    ``all`` expands to console, markdown, html, and json.

    Raises:
        ValueError: A format name is not recognized.
    """
    names = [part.strip().lower() for part in value.split(",") if part.strip()]
    if not names:
        raise ValueError("At least one report format is required.")
    unknown = [name for name in names if name not in FORMAT_NAMES]
    if unknown:
        known = ", ".join(FORMAT_NAMES)
        raise ValueError(f"Unknown format {', '.join(unknown)}. Expected one of: {known}.")
    if "all" in names:
        return ("console", "markdown", "html", "json")
    # Preserve order while dropping duplicates.
    chosen: list[str] = []
    for name in names:
        if name not in chosen:
            chosen.append(name)
    return tuple(chosen)


def parse_only(value: str | None) -> tuple[str, ...] | None:
    """Parse ``--only`` into check names.

    ``None`` means every enabled check.

    Raises:
        ValueError: A check name is not recognized.
    """
    if value is None:
        return None
    names = [part.strip() for part in value.split(",") if part.strip()]
    if not names:
        raise ValueError("`--only` needs at least one check name.")
    unknown = [name for name in names if name not in CHECK_NAMES]
    if unknown:
        known = ", ".join(CHECK_NAMES)
        raise ValueError(f"Unknown check names: {', '.join(unknown)}. Expected one of: {known}.")
    chosen: list[str] = []
    for name in names:
        if name not in chosen:
            chosen.append(name)
    return tuple(chosen)


def format_summary(report: Report) -> str:
    """Return a plain-text summary of a report.

    This is the phase-one console view. Rich and file reports replace it later.
    """
    lines: list[str] = []
    if not report.results:
        lines.append("No checks ran.")
    for result in report.results:
        lines.append(_result_line(result, report))
        if result.error:
            lines.append(f"  error: {result.error}")
        for finding in result.findings:
            lines.append(f"  {_finding_line(finding)}")
    lines.append(f"exit: {report.exit_code()}")
    return "\n".join(lines)


def _result_line(result: CheckResult, report: Report) -> str:
    if result.error:
        status = "ERROR"
    elif result.failed_tests > 0 or any(
        finding.severity.at_least(report.fail_on) for finding in result.findings
    ):
        status = "FAIL"
    else:
        status = "PASS"
    return (
        f"{result.check}: {status} "
        f"findings={len(result.findings)} "
        f"tests={result.passed_tests} passed, {result.failed_tests} failed, "
        f"{result.skipped_tests} skipped"
    )


def _finding_line(finding: Finding) -> str:
    if finding.file and finding.line is not None:
        location = f"{finding.file}:{finding.line}"
    elif finding.file:
        location = finding.file
    elif finding.line is not None:
        location = f"line {finding.line}"
    else:
        location = "-"
    return f"[{finding.severity.value}] {finding.rule_id} {location} {finding.message}"


if __name__ == "__main__":
    sys.exit(main())
