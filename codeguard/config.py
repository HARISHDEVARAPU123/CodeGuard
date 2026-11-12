"""Load CodeGuard settings from ``codeguard.yml``."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path

from codeguard.models import CHECK_NAMES, Severity, parse_severity


class ConfigError(Exception):
    """The configuration file is missing, unreadable, or invalid."""


DEFAULT_EXCLUDES: tuple[str, ...] = (
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    "target",
    "dist",
    "build",
    "htmlcov",
    "*.egg-info",
    "tests/fixtures",
    "sample-java-app/src/demo-bad",
)

_TOP_LEVEL_KEYS = frozenset({"fail_on", "checks", "excludes", "secrets", "formatting", "tests"})
_FORMATTERS = frozenset({"ruff", "black"})


@dataclass
class Config:
    """Runtime settings for one CodeGuard run."""

    fail_on: Severity = Severity.HIGH
    checks: dict[str, bool] = field(default_factory=lambda: {name: True for name in CHECK_NAMES})
    excludes: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    entropy_threshold: float = 4.0
    python_formatter: str = "ruff"
    pytest_args: list[str] = field(default_factory=list)
    maven_args: list[str] = field(default_factory=list)
    source_path: Path | None = None

    def check_enabled(self, name: str) -> bool:
        """Return True when ``name`` is enabled in this config."""
        return self.checks.get(name, False)


def default_config() -> Config:
    """Return built-in settings used when no config file is present."""
    return Config()


def load_config(path: Path) -> Config:
    """Load a YAML config file.

    Raises:
        ConfigError: The file cannot be read or does not match the schema.
    """
    try:
        import yaml
    except ImportError as exc:
        raise ConfigError(
            'PyYAML is not installed. Install CodeGuard with: python -m pip install -e ".[dev]"'
        ) from exc

    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Could not read config file {path}: {exc}") from exc

    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in {path}: {exc}") from exc

    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ConfigError(f"Config root must be a mapping: {path}")

    config = _config_from_mapping(raw)
    config.source_path = path
    return config


def resolve_config(repo: Path, config_path: Path | None) -> Config:
    """Load ``config_path``, or ``repo/codeguard.yml`` when it exists.

    An omitted path with no ``codeguard.yml`` in the repo uses built-in defaults.
    An explicit path that does not exist raises ``ConfigError``.
    """
    if config_path is None:
        candidate = repo / "codeguard.yml"
        if candidate.is_file():
            return load_config(candidate)
        return default_config()
    if not config_path.is_file():
        raise ConfigError(f"Config file not found: {config_path}")
    return load_config(config_path)


def is_excluded(path: str, excludes: list[str] | tuple[str, ...]) -> bool:
    """Return True when a repo-relative path matches an exclude pattern.

    A pattern with no slash matches any path segment, so ``__pycache__`` skips
    ``pkg/__pycache__/foo.pyc``. A pattern with a slash is relative to the
    repository root and also covers everything under that directory.
    ``*`` and ``?`` are glob characters.
    """
    normalized = _normalize_relative(path)
    if normalized == "":
        return False
    parts = normalized.split("/")
    for raw_pattern in excludes:
        pattern = _normalize_relative(raw_pattern).rstrip("/")
        if pattern == "":
            continue
        has_glob = any(token in pattern for token in "*?")
        if has_glob and "/" not in pattern:
            if any(fnmatch.fnmatch(part, pattern) for part in parts):
                return True
            continue
        if has_glob:
            if fnmatch.fnmatch(normalized, pattern) or fnmatch.fnmatch(normalized, pattern + "/*"):
                return True
            continue
        if "/" not in pattern:
            if pattern in parts:
                return True
            continue
        if normalized == pattern or normalized.startswith(pattern + "/"):
            return True
    return False


def to_repo_relative(path: Path, root: Path) -> str:
    """Return ``path`` relative to ``root`` using forward slashes."""
    root_resolved = root.resolve()
    candidate = path if path.is_absolute() else root_resolved / path
    try:
        relative = candidate.resolve().relative_to(root_resolved)
    except ValueError:
        relative = candidate
    return _normalize_relative(relative.as_posix())


def _config_from_mapping(raw: dict[object, object]) -> Config:
    unknown = sorted(str(key) for key in raw if str(key) not in _TOP_LEVEL_KEYS)
    if unknown:
        raise ConfigError(f"Unknown config keys: {', '.join(unknown)}.")

    fail_on = Severity.HIGH
    if "fail_on" in raw:
        try:
            fail_on = parse_severity(raw["fail_on"])
        except ValueError as exc:
            raise ConfigError(str(exc)) from exc

    checks = {name: True for name in CHECK_NAMES}
    if "checks" in raw:
        checks_raw = raw["checks"]
        if not isinstance(checks_raw, dict):
            raise ConfigError("checks must be a mapping of check name to boolean.")
        for key, value in checks_raw.items():
            name = str(key)
            if name not in checks:
                known = ", ".join(CHECK_NAMES)
                raise ConfigError(f"Unknown check {name!r}. Expected one of: {known}.")
            if not isinstance(value, bool):
                raise ConfigError(f"checks.{name} must be true or false.")
            checks[name] = value

    excludes = list(DEFAULT_EXCLUDES)
    if "excludes" in raw:
        excludes = _string_list(raw["excludes"], "excludes")

    entropy_threshold = 4.0
    if "secrets" in raw:
        secrets_raw = _section(raw["secrets"], "secrets")
        if "entropy_threshold" in secrets_raw:
            entropy_threshold = _positive_number(
                secrets_raw["entropy_threshold"], "secrets.entropy_threshold"
            )
        extra = sorted(str(key) for key in secrets_raw if str(key) != "entropy_threshold")
        if extra:
            raise ConfigError(f"Unknown secrets keys: {', '.join(extra)}.")

    python_formatter = "ruff"
    if "formatting" in raw:
        formatting_raw = _section(raw["formatting"], "formatting")
        if "python" in formatting_raw:
            formatter = formatting_raw["python"]
            if not isinstance(formatter, str) or formatter not in _FORMATTERS:
                raise ConfigError("formatting.python must be 'ruff' or 'black'.")
            python_formatter = formatter
        extra = sorted(str(key) for key in formatting_raw if str(key) != "python")
        if extra:
            raise ConfigError(f"Unknown formatting keys: {', '.join(extra)}.")

    pytest_args: list[str] = []
    maven_args: list[str] = []
    if "tests" in raw:
        tests_raw = _section(raw["tests"], "tests")
        if "pytest_args" in tests_raw:
            pytest_args = _string_list(tests_raw["pytest_args"], "tests.pytest_args")
        if "maven_args" in tests_raw:
            maven_args = _string_list(tests_raw["maven_args"], "tests.maven_args")
        extra = sorted(
            str(key) for key in tests_raw if str(key) not in {"pytest_args", "maven_args"}
        )
        if extra:
            raise ConfigError(f"Unknown tests keys: {', '.join(extra)}.")

    return Config(
        fail_on=fail_on,
        checks=checks,
        excludes=excludes,
        entropy_threshold=entropy_threshold,
        python_formatter=python_formatter,
        pytest_args=pytest_args,
        maven_args=maven_args,
    )


def _section(value: object, label: str) -> dict[object, object]:
    if not isinstance(value, dict):
        raise ConfigError(f"{label} must be a mapping.")
    return value


def _string_list(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ConfigError(f"{label} must be a list of strings.")
    return list(value)


def _positive_number(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{label} must be a number.")
    number = float(value)
    if number < 0:
        raise ConfigError(f"{label} must be zero or greater.")
    return number


def _normalize_relative(path: str) -> str:
    normalized = path.replace("\\", "/").strip()
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized.lstrip("/")
