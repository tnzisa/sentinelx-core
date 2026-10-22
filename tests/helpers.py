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


def make_process_raw(**overrides):
    raw = {
        "event_type": "process_execution",
        "timestamp": "2026-10-10T09:31:00Z",
        "source": "endpoint-agent",
        "username": "alice",
        "source_ip": "10.0.0.31",
        "command": "powershell -EncodedCommand AAAA",
    }
    return raw | overrides
