import pytest
from pydantic import ValidationError

from sentinelx.engine import AnalysisResult, analyze
from sentinelx.events import parse_event
from sentinelx.scoring import RiskLevel
from tests.helpers import make_auth_raw, make_process_raw

ENCODED_PS = "powershell.exe -EncodedCommand ABC123"


@pytest.fixture
def three_rule_events():
    return [
        parse_event(make_auth_raw(failed_attempts=8)),
        parse_event(make_auth_raw(failed_attempts=0, privileged=True)),
        parse_event(make_process_raw(command=ENCODED_PS)),
    ]


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


def test_analyze_with_all_three_rules_triggered(three_rule_events):
    result = analyze(three_rule_events)

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


def test_findings_follow_rule_order_for_one_event():
    event = parse_event(make_auth_raw(failed_attempts=8, privileged=True))

    result = analyze([event])

    assert [f.rule_id for f in result.findings] == [
        "failed_logins",
        "privileged_activity",
    ]


def test_analysis_result_is_immutable():
    result = analyze([])

    with pytest.raises(ValidationError):
        result.score = 50
    assert result.score == 0


def test_reversing_event_order_preserves_score_and_risk(three_rule_events):
    forward = analyze(three_rule_events)
    reverse = analyze(list(reversed(three_rule_events)))

    assert reverse.score == forward.score
    assert reverse.risk_level == forward.risk_level


def test_analyzing_same_events_twice_is_deterministic(three_rule_events):
    first = analyze(three_rule_events)
    second = analyze(three_rule_events)

    assert first == second


def test_analyze_rejects_non_event_input():
    with pytest.raises(TypeError):
        analyze([make_auth_raw()])
