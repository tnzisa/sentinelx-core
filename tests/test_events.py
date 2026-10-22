import pytest
from pydantic import ValidationError

from sentinelx.events import AuthenticationEvent, ProcessExecutionEvent, parse_event
from tests.helpers import make_auth_raw, make_process_raw


def test_parse_valid_authentication_event():
    event = parse_event(make_auth_raw())
    assert isinstance(event, AuthenticationEvent)
    assert event.username == "admin"
    assert event.failed_attempts == 8
    assert event.privileged is False


def test_parse_valid_process_execution_event():
    event = parse_event(make_process_raw())
    assert isinstance(event, ProcessExecutionEvent)
    assert event.username == "alice"
    assert event.command.startswith("powershell")


@pytest.mark.parametrize(
    ("overrides", "bad_field"),
    [
        ({"failed_attempts": -1}, "failed_attempts"),
        ({"timestamp": "2026-10-10T09:30:00"}, "timestamp"),  # no timezone
        ({"faild_attempts": 8}, "faild_attempts"),  # misspelled field
        ({"username": ""}, "username"),
        ({"source_ip": "not-an-ip"}, "source_ip"),
        ({"username": "a" * 257}, "username"),
    ],
)
def test_invalid_authentication_events_are_rejected(overrides, bad_field):
    with pytest.raises(ValidationError) as exc_info:
        parse_event(make_auth_raw(**overrides))
    assert exc_info.value.errors()[0]["loc"][-1] == bad_field


def test_unknown_event_type_is_rejected():
    with pytest.raises(ValidationError) as exc_info:
        parse_event(make_auth_raw(event_type="login"))
    assert exc_info.value.errors()[0]["type"] == "union_tag_invalid"


def test_process_event_cannot_carry_authentication_fields():
    with pytest.raises(ValidationError) as exc_info:
        parse_event(make_process_raw(failed_attempts=8))
    assert exc_info.value.errors()[0]["type"] == "extra_forbidden"


def test_process_event_requires_a_command():
    raw = make_process_raw()
    del raw["command"]
    with pytest.raises(ValidationError) as exc_info:
        parse_event(raw)
    assert exc_info.value.errors()[0]["type"] == "missing"


def test_events_are_immutable():
    event = parse_event(make_auth_raw())
    with pytest.raises(ValidationError):
        event.username = "mallory"
    assert event.username == "admin"


def test_username_at_maximum_length_is_accepted():
    event = parse_event(make_auth_raw(username="a" * 256))
    assert len(event.username) == 256
