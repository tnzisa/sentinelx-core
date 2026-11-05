import pytest
from pydantic import ValidationError

from sentinelx.engine import RULES, AnalysisResult, analyze
from sentinelx.events import parse_event
from sentinelx.rules import (
    failed_logins,
    privileged_activity,
    suspicious_command,
)
from sentinelx.scoring import RiskLevel
from tests.helpers import make_auth_raw, make_process_raw


def test_analyze_with_no_events():
    result = analyze([])

    assert isinstance(result, AnalysisResult)
    assert result.score == 0
    assert result.risk_level == RiskLevel.LOW
    assert result.findings == ()
    assert result.event_count == 0


def test_analyze_with_benign_events():
    events = [
        parse_event(make_auth_raw(failed_attempts=1)),
        parse_event(make_process_raw(command="notepad.exe")),
    ]

    result = analyze(events)

    assert result.score == 0
    assert result.risk_level == RiskLevel.LOW
    assert result.findings == ()
    assert result.event_count == 2


def test_analyze_with_all_three_rules_triggered():
    events = [
        parse_event(make_auth_raw(failed_attempts=8)),
        parse_event(make_auth_raw(failed_attempts=0, privileged=True)),
        parse_event(make_process_raw(command="powershell.exe -EncodedCommand ABC123")),
    ]

    result = analyze(events)

    assert result.score == 95
    assert result.risk_level == RiskLevel.CRITICAL
    assert len(result.findings) == 3
    assert result.event_count == 3


def test_analyze_authentication_event_can_trigger_two_rules():
    event = parse_event(make_auth_raw(failed_attempts=8, privileged=True))

    result = analyze([event])

    assert result.score == 55
    assert result.risk_level == RiskLevel.MEDIUM
    assert len(result.findings) == 2
    assert result.event_count == 1


def test_repeated_failed_login_events_do_not_increase_rule_weight():
    events = [parse_event(make_auth_raw(failed_attempts=8)) for _ in range(10)]

    result = analyze(events)

    assert result.score == 30
    assert result.risk_level == RiskLevel.MEDIUM
    assert len(result.findings) == 10
    assert result.event_count == 10


def test_rule_order_is_fixed():
    expected_order = (
        failed_logins,
        privileged_activity,
        suspicious_command,
    )

    assert RULES == expected_order
    assert isinstance(RULES, tuple)


def test_analysis_result_is_immutable():
    result = analyze([])
    with pytest.raises(ValidationError):
        result.score = 50
    assert result.score == 0


def test_reversing_event_order_preserves_score_and_risk():
    events = [
        parse_event(make_auth_raw(failed_attempts=8)),
        parse_event(make_auth_raw(privileged=True)),
        parse_event(make_process_raw(command="powershell.exe -EncodedCommand ABC123")),
    ]

    forward_result = analyze(events)
    reverse_result = analyze(list(reversed(events)))

    assert reverse_result.score == forward_result.score
    assert reverse_result.risk_level == forward_result.risk_level


def test_analyzing_same_events_twice_is_deterministic():
    events = [
        parse_event(make_auth_raw(failed_attempts=8)),
        parse_event(make_auth_raw(privileged=True)),
        parse_event(make_process_raw(command="powershell.exe -EncodedCommand ABC123")),
    ]

    first_result = analyze(events)
    second_result = analyze(events)

    assert first_result == second_result
