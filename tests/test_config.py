"""Tests for config loading and path excludes."""

from pathlib import Path

import pytest

from codeguard.config import (
    DEFAULT_EXCLUDES,
    ConfigError,
    default_config,
    is_excluded,
    load_config,
    resolve_config,
    to_repo_relative,
)
from codeguard.models import Severity

ROOT = Path(__file__).resolve().parents[1]
SELF_SCAN_PATHS = ("tests/fixtures", "sample-java-app/src/demo-bad")


def test_default_config_excludes_intentional_fakes() -> None:
    config = default_config()
    assert config.fail_on is Severity.HIGH
    assert config.python_formatter == "ruff"
    assert config.entropy_threshold == 4.0
    for name in ("formatting", "static_analysis", "tests", "secrets"):
        assert config.check_enabled(name)
    for path in SELF_SCAN_PATHS:
        assert path in config.excludes


def test_repo_config_and_ignore_file_skip_fakes() -> None:
    config = load_config(ROOT / "codeguard.yml")
    for path in SELF_SCAN_PATHS:
        assert path in config.excludes
        assert is_excluded(path + "/fake.txt", config.excludes)

    ignore_lines = (ROOT / ".codeguard-ignore").read_text(encoding="utf-8").splitlines()
    patterns = [
        line.strip().rstrip("/")
        for line in ignore_lines
        if line.strip() and not line.startswith("#")
    ]
    for path in SELF_SCAN_PATHS:
        assert path in patterns


def test_explicit_excludes_replace_the_default_list(tmp_path: Path) -> None:
    path = tmp_path / "codeguard.yml"
    path.write_text("excludes:\n  - only-this\n", encoding="utf-8")
    config = load_config(path)
    assert config.excludes == ["only-this"]
    assert "tests/fixtures" in DEFAULT_EXCLUDES


def test_load_config_reads_sections(tmp_path: Path) -> None:
    path = tmp_path / "codeguard.yml"
    path.write_text(
        "\n".join(
            [
                "fail_on: low",
                "checks:",
                "  secrets: false",
                "secrets:",
                "  entropy_threshold: 5",
                "formatting:",
                "  python: black",
                "tests:",
                "  pytest_args: ['-q']",
                "  maven_args: ['-DskipITs']",
            ]
        ),
        encoding="utf-8",
    )
    config = load_config(path)
    assert config.fail_on is Severity.LOW
    assert config.check_enabled("secrets") is False
    assert config.check_enabled("formatting") is True
    assert config.entropy_threshold == 5.0
    assert config.python_formatter == "black"
    assert config.pytest_args == ["-q"]
    assert config.maven_args == ["-DskipITs"]
    assert config.source_path == path


def test_missing_explicit_config_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError, match="not found"):
        resolve_config(tmp_path, tmp_path / "missing.yml")


def test_omitted_config_uses_defaults_when_file_is_absent(tmp_path: Path) -> None:
    config = resolve_config(tmp_path, None)
    assert config.source_path is None
    assert config.fail_on is Severity.HIGH


def test_omitted_config_loads_repo_file(tmp_path: Path) -> None:
    (tmp_path / "codeguard.yml").write_text("fail_on: MEDIUM\n", encoding="utf-8")
    config = resolve_config(tmp_path, None)
    assert config.fail_on is Severity.MEDIUM


@pytest.mark.parametrize(
    ("raw", "match"),
    [
        ("fail_on: [1]\n", "Severity must be a string"),
        ("fail_on: urgent\n", "Unknown severity"),
        ("checks: true\n", "checks must be a mapping"),
        ("checks:\n  typo: true\n", "Unknown check"),
        ("checks:\n  secrets: 1\n", "true or false"),
        ("excludes: '.git'\n", "list of strings"),
        ("secrets: []\n", "secrets must be a mapping"),
        ("secrets:\n  entropy_threshold: true\n", "must be a number"),
        ("secrets:\n  entropy_threshold: -1\n", "zero or greater"),
        ("formatting:\n  python: prettier\n", "ruff' or 'black"),
        ("nope: 1\n", "Unknown config keys"),
        ("fail_on: [\n", "Invalid YAML"),
    ],
)
def test_invalid_config_raises(tmp_path: Path, raw: str, match: str) -> None:
    path = tmp_path / "codeguard.yml"
    path.write_text(raw, encoding="utf-8")
    with pytest.raises(ConfigError, match=match):
        load_config(path)


def test_empty_file_uses_defaults(tmp_path: Path) -> None:
    path = tmp_path / "codeguard.yml"
    path.write_text("", encoding="utf-8")
    config = load_config(path)
    assert config.excludes == list(DEFAULT_EXCLUDES)


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("pkg/__pycache__/foo.pyc", True),
        ("tests/fixtures/secrets/token.txt", True),
        ("tests/fixtures", True),
        ("tests/fixtures_extra/a.py", False),
        ("sample-java-app/src/demo-bad/java/Bad.java", True),
        ("codeguard.egg-info/PKG-INFO", True),
        (".git/config", True),
        ("src/Main.java", False),
        ("./tests/fixtures/a.txt", True),
    ],
)
def test_is_excluded(path: str, expected: bool) -> None:
    assert is_excluded(path, DEFAULT_EXCLUDES) is expected


def test_to_repo_relative_uses_forward_slashes(tmp_path: Path) -> None:
    target = tmp_path / "src" / "App.java"
    target.parent.mkdir()
    target.write_text("class App {}", encoding="utf-8")
    assert to_repo_relative(target, tmp_path) == "src/App.java"
