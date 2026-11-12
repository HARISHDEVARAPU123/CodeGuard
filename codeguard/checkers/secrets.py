"""Scan a repository for credentials.

Known token shapes are matched with regular expressions. Generic
``password=`` and ``api_key=`` assignments are reported only when the value
is long enough and its Shannon entropy meets the configured threshold.
Matched values are masked to the first four characters before they are stored
on a finding.
"""

from __future__ import annotations

import math
import os
import re
import shutil
import subprocess
from collections import Counter
from pathlib import Path

from codeguard.checkers.base import Checker
from codeguard.config import Config, is_excluded, to_repo_relative
from codeguard.models import CheckResult, Finding, Severity

GIT_INSTALL_HINT = (
    "git is not installed, so the PR diff cannot be scanned. "
    "Install Git from https://git-scm.com/downloads and ensure `git` is on PATH."
)

_MAX_BYTES = 1_000_000
_MIN_ASSIGNMENT_LENGTH = 8

_ALLOW = re.compile(r"codeguard:allow\b")
_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
_AWS_ACCESS = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_AWS_SECRET = re.compile(
    r"(?i)\baws_secret_access_key\b\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})"
)
_GITHUB = re.compile(
    r"\b(?:ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|ghu_[A-Za-z0-9]{36}|"
    r"ghs_[A-Za-z0-9]{36}|ghr_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{20,})\b"
)
_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |OPENSSH |EC |DSA |ENCRYPTED )?PRIVATE KEY-----"
)
_JWT = re.compile(
    r"(?<![A-Za-z0-9_-])"
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
    r"(?![A-Za-z0-9_-])"
)
_ASSIGN = re.compile(
    r"(?i)(?<![A-Za-z0-9])"
    r"(?:password|passwd|pwd|api_key|apikey|api_secret|secret|secret_key|access_key)"
    r"(?![A-Za-z0-9])"
    r"\s*[=:]\s*['\"]?"
    r"([A-Za-z0-9+/_.:\-]{8,})"
)

_PLACEHOLDERS = frozenset(
    {
        "changeme",
        "password",
        "secret",
        "example",
        "placeholder",
        "your-password",
        "your_password",
        "your-api-key",
        "your_api_key",
        "redacted",
        "none",
        "null",
        "todo",
        "fixme",
        "xxxxxxxx",
    }
)
_BINARY_SUFFIXES = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".ico",
        ".pdf",
        ".zip",
        ".jar",
        ".war",
        ".class",
        ".pyc",
        ".so",
        ".dll",
        ".exe",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".mp3",
        ".mp4",
        ".gz",
        ".7z",
        ".bin",
        ".wasm",
    }
)
_SKIP_FILE_NAMES = frozenset(
    {
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "cargo.lock",
    }
)


def mask_secret(value: str) -> str:
    """Mask a secret so reports keep only its first four characters.

    Shorter values are replaced entirely. The returned text never contains
    the remainder of ``value``.
    """
    if len(value) < 4:
        return "***"
    return f"{value[:4]}***"


def shannon_entropy(value: str) -> float:
    """Return the Shannon entropy of ``value`` in bits per character."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def load_ignore_patterns(repo: Path) -> list[str]:
    """Read ``.codeguard-ignore`` from ``repo``.

    Blank lines and ``#`` comments are dropped. A missing file yields an empty list.
    """
    path = repo / ".codeguard-ignore"
    if not path.is_file():
        return []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    patterns: list[str] = []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        patterns.append(stripped)
    return patterns


def find_secrets_in_text(
    relative_path: str, text: str, entropy_threshold: float
) -> list[Finding]:
    """Return secret findings in ``text`` using 1-based line numbers."""
    findings: list[Finding] = []
    for number, line in enumerate(text.splitlines(), start=1):
        findings.extend(find_secrets_in_line(relative_path, number, line, entropy_threshold))
    return findings


def find_secrets_in_line(
    relative_path: str,
    line_number: int,
    line: str,
    entropy_threshold: float,
) -> list[Finding]:
    """Return secret findings on a single line.

    A line containing ``codeguard:allow`` is ignored. Generic assignments that
    overlap a more specific match are not reported a second time.
    """
    if _ALLOW.search(line):
        return []

    findings: list[Finding] = []
    covered: list[tuple[int, int]] = []

    def add(rule_id: str, summary: str, secret: str, start: int, end: int) -> None:
        findings.append(
            Finding(
                check="secrets",
                severity=Severity.CRITICAL,
                file=relative_path,
                line=line_number,
                message=f"{summary} ({mask_secret(secret)}).",
                rule_id=rule_id,
            )
        )
        covered.append((start, end))

    for match in _AWS_ACCESS.finditer(line):
        add("secrets.aws-access-key", "AWS access key ID detected", match.group(0), *match.span())
    for match in _AWS_SECRET.finditer(line):
        add(
            "secrets.aws-secret-key",
            "AWS secret access key detected",
            match.group(1),
            *match.span(1),
        )
    for match in _GITHUB.finditer(line):
        add("secrets.github-token", "GitHub token detected", match.group(0), *match.span())
    for match in _PRIVATE_KEY.finditer(line):
        add("secrets.private-key", "Private key header detected", match.group(0), *match.span())
    for match in _JWT.finditer(line):
        add("secrets.jwt", "JSON Web Token detected", match.group(0), *match.span())

    for match in _ASSIGN.finditer(line):
        start, end = match.span(1)
        if any(start < right and end > left for left, right in covered):
            continue
        value = match.group(1)
        if value.casefold() in _PLACEHOLDERS:
            continue
        if shannon_entropy(value) < entropy_threshold:
            continue
        add("secrets.assignment", "High-entropy secret assignment", value, start, end)
    return findings


def added_lines_from_diff(diff_text: str) -> list[tuple[str, int, str]]:
    """Return added lines from a unified diff as ``(path, line, text)``.

    Removed lines are omitted. Secrets that a change deletes are no longer in
    the tree, and the working-tree scan covers lines that remain.
    """
    current: str | None = None
    new_line: int | None = None
    added: list[tuple[str, int, str]] = []
    for raw in diff_text.splitlines():
        if raw.startswith("+++ "):
            current = _path_from_diff_header(raw[4:])
            new_line = None
            continue
        if raw.startswith(("--- ", "diff --git ")):
            continue
        hunk = _HUNK.match(raw)
        if hunk:
            new_line = int(hunk.group(1))
            continue
        if current is None or new_line is None:
            continue
        if raw.startswith("+"):
            added.append((current, new_line, raw[1:]))
            new_line += 1
            continue
        if raw.startswith("-") or raw.startswith("\\"):
            continue
        new_line += 1
    return added


class SecretsChecker(Checker):
    """Find credentials in the working tree and in added git-diff lines."""

    def __init__(self) -> None:
        super().__init__("secrets")

    def run(self, path: Path, config: Config) -> CheckResult:
        """Scan ``path`` and return one critical finding per match.

        ``.git`` is never walked. A missing ``git`` binary is a tool error, and
        the working-tree findings are still returned. A directory that is not a
        git repository is scanned as a tree only.
        """
        repo = path.resolve()
        patterns = [*config.excludes, *load_ignore_patterns(repo)]
        findings: list[Finding] = []
        seen: set[tuple[str | None, int | None, str, str]] = set()

        def add(found: list[Finding]) -> None:
            for finding in found:
                key = (finding.file, finding.line, finding.rule_id, finding.message)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(finding)

        for file_path in _iter_files(repo, patterns):
            text = _read_text(file_path)
            if text is None:
                continue
            add(
                find_secrets_in_text(
                    _relative(file_path, repo),
                    text,
                    config.entropy_threshold,
                )
            )

        error = _scan_diff(repo, patterns, config.entropy_threshold, add)
        findings.sort(key=lambda finding: (finding.file or "", finding.line or 0, finding.rule_id))
        return CheckResult(check=self.name, findings=findings, error=error)


def _scan_diff(
    repo: Path,
    patterns: list[str],
    entropy_threshold: float,
    add: object,
) -> str | None:
    git = shutil.which("git")
    if git is None:
        return GIT_INSTALL_HINT
    if not _inside_work_tree(repo, git):
        return None

    added, error = _git_added_lines(repo, git)
    # ``add`` is the dedupe helper from ``run``. Keeping it untyped avoids a
    # callback protocol for one call site.
    record = add
    for relative, line_number, line in added:
        if is_excluded(relative, patterns):
            continue
        record(find_secrets_in_line(relative, line_number, line, entropy_threshold))  # type: ignore[operator]
    return error


def _iter_files(repo: Path, patterns: list[str]) -> list[Path]:
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(repo):
        relative_dir = _relative(Path(dirpath), repo)
        kept: list[str] = []
        for name in dirnames:
            if name == ".git":
                continue
            child = f"{relative_dir}/{name}" if relative_dir else name
            if not is_excluded(child, patterns):
                kept.append(name)
        dirnames[:] = kept
        for name in filenames:
            relative = f"{relative_dir}/{name}" if relative_dir else name
            if is_excluded(relative, patterns):
                continue
            found.append(Path(dirpath) / name)
    return found


def _read_text(path: Path) -> str | None:
    if path.name in _SKIP_FILE_NAMES or path.suffix.lower() in _BINARY_SUFFIXES:
        return None
    try:
        if path.stat().st_size > _MAX_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data:
        return None
    return data.decode("utf-8", errors="replace")


def _relative(path: Path, root: Path) -> str:
    relative = to_repo_relative(path, root)
    if relative == ".":
        return ""
    return relative


def _inside_work_tree(repo: Path, git: str) -> bool:
    completed = _run_git(repo, git, ["rev-parse", "--is-inside-work-tree"])
    if completed is None or completed.returncode != 0:
        return False
    return completed.stdout.strip() == "true"


def _git_added_lines(
    repo: Path, git: str
) -> tuple[list[tuple[str, int, str]], str | None]:
    commands = [
        ["diff", "--unified=0", "--no-ext-diff", "--no-color"],
        ["diff", "--cached", "--unified=0", "--no-ext-diff", "--no-color"],
    ]
    base = os.environ.get("GITHUB_BASE_REF") or os.environ.get("CODEGUARD_BASE_REF")
    if base:
        commands.append(
            ["diff", "--unified=0", "--no-ext-diff", "--no-color", f"origin/{base}...HEAD"]
        )
    added: list[tuple[str, int, str]] = []
    for args in commands:
        completed = _run_git(repo, git, args)
        if completed is None:
            return added, "git diff timed out after 30 seconds."
        if completed.returncode != 0:
            continue
        added.extend(added_lines_from_diff(completed.stdout))
    return added, None


def _run_git(
    repo: Path, git: str, args: list[str]
) -> subprocess.CompletedProcess[str] | None:
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    try:
        return subprocess.run(
            [git, *args],
            cwd=repo,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            check=False,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return None


def _path_from_diff_header(header: str) -> str | None:
    path = header.strip()
    if len(path) >= 2 and path[0] == '"' and path[-1] == '"':
        path = path[1:-1]
    if path.startswith("b/"):
        path = path[2:]
    path = path.replace("\\", "/")
    if path in {"/dev/null", "dev/null"}:
        return None
    return path
