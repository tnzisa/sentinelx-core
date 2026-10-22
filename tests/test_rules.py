from sentinelx.events import parse_event
from sentinelx.rules import Finding, failed_logins
from tests.helpers import make_auth_raw, make_process_raw


def test_failed_logins_fires_at_threshold():
    event = parse_event(make_auth_raw(failed_attempts=5))
    finding = failed_logins(event)
    assert isinstance(finding, Finding)
    assert finding.rule_id == "failed_logins"
    assert finding.event_id == event.event_id


def test_failed_logins_does_not_fire_below_threshold():
    event = parse_event(make_auth_raw(failed_attempts=4))
    finding = failed_logins(event)
    assert finding is None


def test_failed_logins_does_not_fire_on_process_execution_event():
    event = parse_event(make_process_raw())
    finding = failed_logins(event)
    assert finding is None
