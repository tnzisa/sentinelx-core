from sentinelx.events import AuthenticationEvent, parse_event


def make_auth_raw(**overrides):
    raw = {
        "event_type": "authentication",
        "timestamp": "2026-10-10T09:30:00Z",
        "source": "vpn-gateway",
        "username": "admin",
        "source_ip": "10.0.0.25",
        "failed_attempts": 8,
    }
    return raw | overrides


def test_parse_valid_authentication_event():
    event = parse_event(make_auth_raw())
    assert isinstance(event, AuthenticationEvent)
    assert event.username == "admin"
    assert event.failed_attempts == 8
    assert event.privileged is False
