import json
import logging
import sys
from datetime import UTC, datetime

from sentinelx.engine import AnalysisResult

logger = logging.getLogger("sentinelx.analysis")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        payload.update(getattr(record, "fields", {}))
        return json.dumps(payload, sort_keys=True)


def configure_logging(level: int = logging.INFO) -> None:
    logger = logging.getLogger("sentinelx")
    logger.setLevel(level)
    logger.propagate = False
    if not any(isinstance(h.formatter, JsonFormatter) for h in logger.handlers):
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)


def log_analysis(result: AnalysisResult) -> None:
    logger.info(
        "analysis_complete",
        extra={
            "fields": {
                "event_count": result.event_count,
                "score": result.score,
                "risk_level": result.risk_level.value,
                "rule_ids": sorted({f.rule_id for f in result.findings}),
            }
        },
    )
