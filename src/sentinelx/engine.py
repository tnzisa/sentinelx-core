from collections.abc import Sequence

from pydantic import BaseModel, ConfigDict

from sentinelx.events import AuthenticationEvent, ProcessExecutionEvent
from sentinelx.rules import (
    Finding,
    failed_logins,
    privileged_activity,
    suspicious_command,
)
from sentinelx.scoring import RiskLevel, score_findings

Event = AuthenticationEvent | ProcessExecutionEvent

RULES = (
    failed_logins,
    privileged_activity,
    suspicious_command,
)


class AnalysisResult(BaseModel):
    model_config = ConfigDict(frozen=True)

    score: int
    risk_level: RiskLevel
    findings: tuple[Finding, ...]
    event_count: int


def analyze(events: Sequence[Event]) -> AnalysisResult:
    findings: list[Finding] = []

    for event in events:
        if not isinstance(event, Event):
            raise TypeError(f"Expected a parsed event, got {type(event).__name__}")

        for rule in RULES:
            finding = rule(event)
            if finding is not None:
                findings.append(finding)

    score_result = score_findings(findings)

    return AnalysisResult(
        score=score_result.score,
        risk_level=score_result.risk_level,
        findings=tuple(findings),
        event_count=len(events),
    )
