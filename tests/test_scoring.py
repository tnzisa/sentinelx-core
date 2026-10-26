import pytest

from sentinelx.rules import Finding
from sentinelx.scoring import (
    MAX_SCORE,
    RULE_WEIGHTS,
    RiskLevel,
    risk_level_for,
    score_findings,
)


def make_finding(rule_id: str) -> Finding:
    return Finding(rule_id=rule_id, title="t", event_id="e1", evidence="x")


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (0, RiskLevel.LOW),
        (29, RiskLevel.LOW),
        (30, RiskLevel.MEDIUM),
        (59, RiskLevel.MEDIUM),
        (60, RiskLevel.HIGH),
        (79, RiskLevel.HIGH),
        (80, RiskLevel.CRITICAL),
        (100, RiskLevel.CRITICAL),
    ],
)
def test_risk_level_for(score, expected):
    assert risk_level_for(score) == expected


def test_score_findings_with_no_findings():
    result = score_findings([])

    assert result.score == 0
    assert result.risk_level == RiskLevel.LOW
    assert result.rule_ids == ()


def test_score_findings_with_one_rule():
    result = score_findings([make_finding("failed_logins")])

    assert result.score == 30
    assert result.risk_level == RiskLevel.MEDIUM
    assert result.rule_ids == ("failed_logins",)


def test_score_findings_does_not_double_count_same_rule():
    findings = [
        make_finding("failed_logins"),
        make_finding("failed_logins"),
    ]

    result = score_findings(findings)

    assert result.score == 30
    assert result.rule_ids == ("failed_logins",)


def test_score_findings_with_all_rules_sorts_rule_ids():
    findings = [
        make_finding("suspicious_command"),
        make_finding("failed_logins"),
        make_finding("privileged_activity"),
    ]

    result = score_findings(findings)

    assert result.score == 95
    assert result.risk_level == RiskLevel.CRITICAL
    assert result.rule_ids == (
        "failed_logins",
        "privileged_activity",
        "suspicious_command",
    )


def test_score_findings_rejects_unknown_rule_id():
    findings = [make_finding("unknown_rule")]

    with pytest.raises(ValueError, match="unknown_rule"):
        score_findings(findings)


def test_score_findings_capped_at_max_score(monkeypatch):
    monkeypatch.setitem(RULE_WEIGHTS, "heavy_rule", 90)

    result = score_findings(
        [
            make_finding("heavy_rule"),
            make_finding("failed_logins"),
        ]
    )

    assert result.score == MAX_SCORE
    assert result.risk_level == RiskLevel.CRITICAL
