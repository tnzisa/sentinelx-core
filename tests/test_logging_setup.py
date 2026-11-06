import io
import json
import logging
from datetime import datetime, timedelta

import pytest

from sentinelx.engine import analyze
from sentinelx.events import parse_event
from sentinelx.logging_setup import JsonFormatter, configure_logging, log_analysis
from tests.helpers import make_auth_raw, make_process_raw


@pytest.fixture
def log_stream():
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(JsonFormatter())
    logger = logging.getLogger("sentinelx.test")
    logger.handlers = [handler]
    logger.setLevel(logging.INFO)
    logger.propagate = False
    yield logger, stream
    logger.handlers = []


@pytest.fixture
def clean_logger():
    logger = logging.getLogger("sentinelx")
    saved = (logger.handlers[:], logger.propagate, logger.level)
    logger.handlers = []
    yield logger
    logger.handlers, logger.propagate, logger.level = saved


def test_configure_logging_is_idempotent(clean_logger):
    configure_logging()
    configure_logging()
    assert len(clean_logger.handlers) == 1


def test_log_analysis_records_summary_fields(caplog):
    events = [
        parse_event(make_auth_raw(failed_attempts=8, privileged=True)),
        parse_event(make_process_raw()),
    ]
    result = analyze(events)

    with caplog.at_level(logging.INFO, logger="sentinelx"):
        log_analysis(result)

    fields = caplog.records[0].fields
    assert fields["score"] == 95
    assert fields["risk_level"] == "CRITICAL"
    assert fields["rule_ids"] == [
        "failed_logins",
        "privileged_activity",
        "suspicious_command",
    ]
    assert fields["event_count"] == 2


def test_log_analysis_excludes_sensitive_fields(caplog):
    events = [
        parse_event(make_auth_raw(failed_attempts=8, privileged=True)),
        parse_event(make_process_raw()),
    ]

    result = analyze(events)

    with caplog.at_level(logging.INFO, logger="sentinelx"):
        log_analysis(result)

    record = next(
        record for record in caplog.records if record.name == "sentinelx.analysis"
    )

    assert set(record.fields.keys()) == {
        "event_count",
        "score",
        "risk_level",
        "rule_ids",
    }


def test_json_formatter_staandard_keys(log_stream):
    logger, stream = log_stream
    logger.info("hello")

    payload = json.loads(stream.getvalue())

    assert "timestamp" in payload
    assert "level" in payload
    assert "logger" in payload
    assert "message" in payload
    assert payload["message"] == "hello"


def test_json_formatter_extra_keys(log_stream):
    logger, stream = log_stream
    logger.info("x", extra={"fields": {"score": 95}})

    payload = json.loads(stream.getvalue())

    assert payload["score"] == 95


def test_json_formatter_prevents_log_injection(log_stream):
    logger, stream = log_stream
    logger.info('a\n{"level": "CRITICAL"}')

    output = stream.getvalue()

    assert len(output.splitlines()) == 1


def test_json_formatter_timestamp_is_utc_aware(log_stream):
    logger, stream = log_stream
    logger.info("test")

    timestamp = datetime.fromisoformat(json.loads(stream.getvalue())["timestamp"])

    assert timestamp.tzinfo is not None
    assert timestamp.utcoffset() == timedelta(0)


def test_extra_fields_cannot_override_core_keys(log_stream):
    logger, stream = log_stream
    logger.info(
        "real message",
        extra={"fields": {"level": "CRITICAL", "message": "forged"}},
    )

    payload = json.loads(stream.getvalue())

    assert payload["level"] == "INFO"
    assert payload["message"] == "real message"
