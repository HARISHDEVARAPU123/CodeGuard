"""Tests for the secrets scanner."""

from __future__ import annotations

from pathlib import Path

import pytest

from codeguard.checkers.secrets import (
    GIT_INSTALL_HINT,
    SecretsChecker,
    added_lines_from_diff,
    find_secrets_in_line,
    find_secrets_in_text,
    load_ignore_patterns,
    mask_secret,
    shannon_entropy,
)
from codeguard.config import default_config
from codeguard.models import Severity


def test_mask_secret() -> None:
    assert mask_secret("") == "***"
    assert mask_secret("abc") == "***"
    assert mask_secret("abcd") == "abcd***"
    assert mask_secret("AKIAIOSFODNN7EXAMPLE") == "AKIA***"  # codeguard:allow


def test_shannon_entropy() -> None:
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaaaaa") == 0.0
    assert shannon_entropy("abcdefgh") > 2.5


def test_load_ignore_patterns(tmp_path: Path) -> None:
    assert load_ignore_patterns(tmp_path) == []

    ignore_file = tmp_path / ".codeguard-ignore"
    ignore_file.write_text("# comment\n\nnode_modules/\n*.secret\n", encoding="utf-8")
    patterns = load_ignore_patterns(tmp_path)
    assert patterns == ["node_modules/", "*.secret"]


def test_find_secrets_in_line_aws() -> None:
    key_id = "AKIA" + "IOSFODNN7EXAMPLE"
    findings = find_secrets_in_line("config.env", 1, f"key = {key_id}", 4.0)
    assert len(findings) == 1
    assert findings[0].rule_id == "secrets.aws-access-key"
    assert findings[0].severity == Severity.CRITICAL
    assert "AKIA***" in findings[0].message
    assert key_id not in findings[0].message


def test_find_secrets_in_line_github_tokens() -> None:
    prefixes = ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"]
    for prefix in prefixes:
        token = prefix + ("A" * 36)
        findings = find_secrets_in_line("ci.env", 1, f"TOKEN={token}", 4.0)
        assert len(findings) == 1
        assert findings[0].rule_id == "secrets.github-token"
        assert f"{prefix[:4]}***" in findings[0].message

    pat = "github_pat_" + ("B" * 30)
    findings = find_secrets_in_line("ci.env", 1, f"PAT={pat}", 4.0)
    assert len(findings) == 1
    assert findings[0].rule_id == "secrets.github-token"


def test_find_secrets_in_line_pem_key() -> None:
    line = "-----BEGIN " + "RSA PRIVATE KEY-----"
    findings = find_secrets_in_line("id_rsa", 1, line, 4.0)
    assert len(findings) == 1
    assert findings[0].rule_id == "secrets.private-key"


def test_find_secrets_in_line_jwt() -> None:
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotRealSig123456789"  # noqa: E501 # codeguard:allow
    findings = find_secrets_in_line("token.txt", 1, f"Bearer {jwt}", 4.0)
    assert len(findings) == 1
    assert findings[0].rule_id == "secrets.jwt"


def test_find_secrets_in_line_assignment_entropy() -> None:
    # High entropy assignment
    high_ent = "aB3kL9zP0qW5xY1m"
    findings = find_secrets_in_line("settings.py", 1, f"api_key = '{high_ent}'", 3.0)
    assert len(findings) == 1
    assert findings[0].rule_id == "secrets.assignment"

    # Low entropy assignment
    low_ent = "aaaaaaaaaaaaaaaa"
    findings = find_secrets_in_line("settings.py", 1, f"api_key = '{low_ent}'", 3.0)
    assert len(findings) == 0

    # Known placeholder
    findings = find_secrets_in_line("settings.py", 1, "password = 'changeme'", 1.0)
    assert len(findings) == 0


def test_find_secrets_inline_allow_comments() -> None:
    key_id = "AKIA" + "IOSFODNN7EXAMPLE"
    line_python = f"aws_key = '{key_id}'  # codeguard:allow"
    assert find_secrets_in_line("test.py", 1, line_python, 4.0) == []

    line_java = f'String key = "{key_id}"; // codeguard:allow'
    assert find_secrets_in_line("Test.java", 1, line_java, 4.0) == []


def test_find_secrets_in_text() -> None:
    text = f"clean line 1\napi_key = '{'AKIA' + 'IOSFODNN7EXAMPLE'}'\nclean line 3\n"
    findings = find_secrets_in_text("sample.py", text, 4.0)
    assert len(findings) == 1
    assert findings[0].line == 2


def test_added_lines_from_diff() -> None:
    diff_text = (
        "diff --git a/app.py b/app.py\n"
        "--- a/app.py\n"
        "+++ b/app.py\n"
        "@@ -10,3 +10,4 @@\n"
        " existing line\n"
        "+newly added line 1\n"
        "-deleted line\n"
        "+newly added line 2\n"
    )
    added = added_lines_from_diff(diff_text)
    assert added == [
        ("app.py", 11, "newly added line 1"),
        ("app.py", 12, "newly added line 2"),
    ]


def test_secrets_checker_on_fixtures() -> None:
    fixtures_dir = Path(__file__).parent / "fixtures" / "secrets"
    config = default_config()
    config.excludes = []  # allow scanning fixtures for this test
    checker = SecretsChecker()
    result = checker.run(fixtures_dir, config)

    assert result.error is None
    # Verify that clean.env and allowed.py produce no findings
    clean_findings = [f for f in result.findings if f.file and "clean.env" in f.file]
    assert clean_findings == []

    allowed_findings = [f for f in result.findings if f.file and "allowed.py" in f.file]
    assert allowed_findings == []

    # Verify that aws_keys.env, github_tokens.txt, jwt_token.txt, private_key.pem have findings
    rule_ids = {f.rule_id for f in result.findings}
    assert "secrets.aws-access-key" in rule_ids
    assert "secrets.aws-secret-key" in rule_ids
    assert "secrets.github-token" in rule_ids
    assert "secrets.private-key" in rule_ids
    assert "secrets.jwt" in rule_ids
    assert "secrets.assignment" in rule_ids


def test_secrets_checker_git_not_found(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr("shutil.which", lambda cmd: None)
    checker = SecretsChecker()
    result = checker.run(tmp_path, default_config())
    assert result.error == GIT_INSTALL_HINT
