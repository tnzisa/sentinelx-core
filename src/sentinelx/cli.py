import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from pydantic import ValidationError

from sentinelx.engine import AnalysisResult, Event, analyze
from sentinelx.events import parse_event
from sentinelx.logging_setup import configure_logging, log_analysis

EXIT_OK = 0
EXIT_BAD_INPUT = 2


class InputError(Exception):
    """The input could not be turned into valid events."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sentinelx")
    subparsers = parser.add_subparsers(dest="command", required=True)
    analyze_parser = subparsers.add_parser(
        "analyze", help="analyze a JSON file containing a list of events"
    )
    analyze_parser.add_argument("path", type=Path)
    return parser


def load_events(path: Path) -> list[Event]:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise InputError(f"file not found: {path}") from None
    except (OSError, UnicodeDecodeError) as exc:
        raise InputError(f"cannot read file ({type(exc).__name__})") from None

    try:
        raw = json.loads(text)
    except (ValueError, RecursionError):
        raise InputError("file is not valid JSON") from None
    if not isinstance(raw, list):
        raise InputError("top-level JSON value must be a list of events")

    events: list[Event] = []
    problems: list[str] = []
    for index, item in enumerate(raw):
        try:
            events.append(parse_event(item))
        except ValidationError as exc:
            for error in exc.errors():
                field = ".".join(str(part) for part in error["loc"]) or "(event)"
                problems.append(f"event {index}: {field}: {error['type']}")
    if problems:
        raise InputError("\n".join(problems))
    return events


def format_summary(result: AnalysisResult) -> str:
    lines = [
        f"Events analyzed: {result.event_count}",
        f"Risk score: {result.score}",
        f"Risk level: {result.risk_level.value}",
        f"Findings: {len(result.findings)}",
    ]
    for finding in result.findings:
        lines.append(f"  - [{finding.rule_id}] {finding.title}: {finding.evidence}")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging()
    try:
        events = load_events(args.path)
    except InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_BAD_INPUT

    result = analyze(events)
    log_analysis(result)
    print(format_summary(result))
    return EXIT_OK
