import io
import json
import logging
from datetime import datetime

import pytest

from sentinelx.logging_setup import JsonFormatter, configure_logging


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


def test_json_formatter_timestamp_format(log_stream):
    logger, stream = log_stream
    logger.info("test")

    payload = json.loads(stream.getvalue())
    timestamp_str = payload["timestamp"]

    # Check if the timestamp is in ISO 8601 format
    try:
        datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
    except ValueError:
        pytest.fail(f"Timestamp '{timestamp_str}' is not in ISO 8601 format")
