"""Tests verifying sample-java-app clean code vs demo-bad."""

from __future__ import annotations

from pathlib import Path

from codeguard.checkers.secrets import find_secrets_in_text
from codeguard.checkers.static_analysis import scan_java_source


def test_sample_java_clean_files() -> None:
    root = (
        Path(__file__).parent.parent
        / "sample-java-app"
        / "src"
        / "main"
        / "java"
        / "com"
        / "codeguard"
        / "policy"
    )
    policy_file = root / "Policy.java"
    calc_file = root / "PremiumCalculator.java"

    assert policy_file.is_file()
    assert calc_file.is_file()

    policy_findings = scan_java_source("Policy.java", policy_file.read_text(encoding="utf-8"))
    calc_findings = scan_java_source(
        "PremiumCalculator.java", calc_file.read_text(encoding="utf-8")
    )

    assert policy_findings == []
    assert calc_findings == []


def test_sample_java_demo_bad_triggers_findings() -> None:
    bad_file = (
        Path(__file__).parent.parent
        / "sample-java-app"
        / "src"
        / "demo-bad"
        / "BadPolicyService.java"
    )
    assert bad_file.is_file()
    content = bad_file.read_text(encoding="utf-8")

    # 1. Java static analysis findings
    findings = scan_java_source("BadPolicyService.java", content)
    rule_ids = {f.rule_id for f in findings}
    assert "java.empty-catch" in rule_ids
    assert "java.system-out" in rule_ids
    assert "java.string-compare-eq" in rule_ids
    assert "java.print-stack-trace" in rule_ids
    assert "java.todo-fixme" in rule_ids
    assert "java.unused-import" in rule_ids

    # 2. Secrets findings (AKIA...)
    secret_findings = find_secrets_in_text("BadPolicyService.java", content, 4.0)
    assert len(secret_findings) >= 1
    assert any(f.rule_id == "secrets.aws-access-key" for f in secret_findings)
