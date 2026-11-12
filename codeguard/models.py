"""Structured results shared by every checker and report."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum

CHECK_NAMES: tuple[str, ...] = ("formatting", "static_analysis", "tests", "secrets")

_SEVERITY_RANK: dict[str, int] = {
    "LOW": 0,
    "MEDIUM": 1,
    "HIGH": 2,
    "CRITICAL": 3,
}


class Severity(StrEnum):
    """How serious a finding is.

    Ordering is by risk, not by the label text. ``CRITICAL`` is the highest.
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        """Return the numeric rank used for threshold checks."""
        return _SEVERITY_RANK[self.value]

    def at_least(self, threshold: Severity) -> bool:
        """Return True when this severity meets or exceeds ``threshold``."""
        return self.rank >= threshold.rank

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank


def parse_severity(value: object) -> Severity:
    """Parse a severity label.

    Raises:
        ValueError: ``value`` is not a known severity name.
    """
    if isinstance(value, Severity):
        return value
    if not isinstance(value, str):
        raise ValueError(f"Severity must be a string, got {type(value).__name__}.")
    try:
        return Severity(value.strip().upper())
    except ValueError as exc:
        known = ", ".join(level.value for level in Severity)
        raise ValueError(f"Unknown severity {value!r}. Expected one of: {known}.") from exc


@dataclass
class Finding:
    """One issue reported by a checker."""

    check: str
    severity: Severity
    file: str | None
    line: int | None
    message: str
    rule_id: str

    def __post_init__(self) -> None:
        self.severity = parse_severity(self.severity)
        if self.line is not None and self.line < 1:
            raise ValueError("Finding line numbers start at 1.")

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-ready mapping. Severity is the label string."""
        payload = asdict(self)
        payload["severity"] = self.severity.value
        return payload


@dataclass
class CheckResult:
    """Outcome of a single checker, including a tool failure if it could not run."""

    check: str
    findings: list[Finding] = field(default_factory=list)
    passed_tests: int = 0
    failed_tests: int = 0
    skipped_tests: int = 0
    error: str | None = None
    duration_ms: float = 0.0

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-ready mapping."""
        return {
            "check": self.check,
            "findings": [finding.to_dict() for finding in self.findings],
            "passed_tests": self.passed_tests,
            "failed_tests": self.failed_tests,
            "skipped_tests": self.skipped_tests,
            "error": self.error,
            "duration_ms": self.duration_ms,
        }


@dataclass
class Report:
    """Aggregated checker results and the process exit code."""

    results: list[CheckResult]
    fail_on: Severity

    def __post_init__(self) -> None:
        self.fail_on = parse_severity(self.fail_on)

    def gate_failed(self) -> bool:
        """Return True when a finding meets ``fail_on`` or any test failed.

        Test failures always fail the gate. ``fail_on`` does not lower them.
        """
        for result in self.results:
            if result.failed_tests > 0:
                return True
            for finding in result.findings:
                if finding.severity.at_least(self.fail_on):
                    return True
        return False

    def exit_code(self) -> int:
        """Return 2 for a tool error, 1 for a failed gate, and 0 for a pass.

        A tool error wins when both a tool error and a gate failure are present,
        so a crashed checker cannot be reported as a normal gate result.
        """
        if any(result.error for result in self.results):
            return 2
        if self.gate_failed():
            return 1
        return 0

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-ready mapping."""
        return {
            "fail_on": self.fail_on.value,
            "exit_code": self.exit_code(),
            "results": [result.to_dict() for result in self.results],
        }
