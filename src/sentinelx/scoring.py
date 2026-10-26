from collections.abc import Sequence
from enum import StrEnum

from pydantic import BaseModel, ConfigDict

from sentinelx.rules import Finding


class RiskLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


RISK_THRESHOLDS = (
    (80, RiskLevel.CRITICAL),
    (60, RiskLevel.HIGH),
    (30, RiskLevel.MEDIUM),
)

RULE_WEIGHTS = {
    "failed_logins": 30,
    "privileged_activity": 25,
    "suspicious_command": 40,
}
MAX_SCORE = 100


class ScoreResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    score: int
    risk_level: RiskLevel
    rule_ids: tuple[str, ...]


def risk_level_for(score: int) -> RiskLevel:
    for minimum, level in RISK_THRESHOLDS:
        if score >= minimum:
            return level

    return RiskLevel.LOW


def score_findings(findings: Sequence[Finding]) -> ScoreResult:
    rule_ids = tuple(sorted({finding.rule_id for finding in findings}))

    unknown_rule_ids = set(rule_ids) - RULE_WEIGHTS.keys()
    if unknown_rule_ids:
        unknown = ", ".join(sorted(unknown_rule_ids))
        raise ValueError(f"Unknown rule ID(s): {unknown}")

    score = min(
        sum(RULE_WEIGHTS[rule_id] for rule_id in rule_ids),
        MAX_SCORE,
    )

    return ScoreResult(
        score=score,
        risk_level=risk_level_for(score),
        rule_ids=rule_ids,
    )
