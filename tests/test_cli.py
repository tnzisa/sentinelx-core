import json
from pathlib import Path

import pytest

from sentinelx.cli import main
from tests.helpers import make_auth_raw, make_process_raw

pytestmark = pytest.mark.usefixtures("clean_logger")

SCENARIO = [
    make_auth_raw(failed_attempts=8, privileged=True),
    make_process_raw(),
]


def write_events(tmp_path, events):
    path = tmp_path / "events.json"
    path.write_text(json.dumps(events), encoding="utf-8")
    return path


def test_analyze_valid_file_prints_summary(tmp_path, capsys):
    code = main(["analyze", str(write_events(tmp_path, SCENARIO))])
    out = capsys.readouterr().out
    assert code == 0
    assert "Risk score: 95" in out
    assert "Risk level: CRITICAL" in out


def test_analyze_benign_file_returns_low_risk(tmp_path, capsys):
    events = [make_auth_raw(failed_attempts=0, privileged=False)]

    code = main(["analyze", str(write_events(tmp_path, events))])
    out = capsys.readouterr().out

    assert code == 0
    assert "Risk level: LOW" in out


def test_analyze_empty_list(tmp_path, capsys):
    code = main(["analyze", str(write_events(tmp_path, []))])
    out = capsys.readouterr().out

    assert code == 0
    assert "Events analyzed: 0" in out


def test_missing_file_returns_error(tmp_path, capsys):
    code = main(["analyze", str(tmp_path / "missing.json")])
    captured = capsys.readouterr()

    assert code == 2
    assert "file not found" in captured.err.lower()
    assert captured.out == ""


def test_invalid_json_returns_error(tmp_path, capsys):
    path = tmp_path / "invalid.json"
    path.write_text("{not json", encoding="utf-8")

    code = main(["analyze", str(path)])
    captured = capsys.readouterr()

    assert code == 2
    assert "not valid JSON" in captured.err
    assert captured.out == ""


def test_non_list_json_returns_error(tmp_path, capsys):
    code = main(["analyze", str(write_events(tmp_path, {"a": 1}))])
    captured = capsys.readouterr()

    assert code == 2
    assert "list of events" in captured.err
    assert captured.out == ""


def test_bad_event_does_not_expose_input_value(tmp_path, capsys):
    events = [
        make_auth_raw(),
        make_auth_raw(source_ip="SECRET-VALUE"),
    ]

    code = main(["analyze", str(write_events(tmp_path, events))])
    captured = capsys.readouterr()

    assert code == 2
    assert "event 1" in captured.err
    assert "source_ip" in captured.err
    assert "SECRET-VALUE" not in captured.err
    assert captured.out == ""


def test_non_object_event_returns_error(tmp_path, capsys):
    code = main(["analyze", str(write_events(tmp_path, [42]))])
    captured = capsys.readouterr()

    assert code == 2
    assert "event 0" in captured.err
    assert captured.out == ""


def test_analysis_log_is_written_to_stderr(tmp_path, capsys):
    code = main(["analyze", str(write_events(tmp_path, SCENARIO))])
    captured = capsys.readouterr()

    assert code == 0

    log_lines = captured.err.strip().splitlines()
    payload = json.loads(log_lines[-1])

    assert payload["message"] == "analysis_complete"
    assert payload["score"] == 95
    assert "analysis_complete" not in captured.out


def test_no_arguments_exits_with_code_2():
    with pytest.raises(SystemExit) as exc_info:
        main([])

    assert exc_info.value.code == 2


def test_example_events_file_runs_successfully(capsys):
    example_path = Path(__file__).parent.parent / "examples" / "events.json"

    code = main(["analyze", str(example_path)])
    captured = capsys.readouterr()

    assert code == 0
    assert "Risk score: 95" in captured.out
    assert "Risk level: CRITICAL" in captured.out


def test_deeply_nested_json_exits_2(tmp_path, capsys):
    path = tmp_path / "nested.json"
    path.write_text("[" * 200_000, encoding="utf-8")
    assert main(["analyze", str(path)]) == 2


def test_huge_integer_exits_2(tmp_path, capsys):
    path = tmp_path / "bigint.json"
    path.write_text("[" + "1" * 5000 + "]", encoding="utf-8")
    assert main(["analyze", str(path)]) == 2


def test_utf8_bom_file_is_accepted(tmp_path, capsys):
    path = tmp_path / "bom.json"
    path.write_bytes(b"\xef\xbb\xbf" + json.dumps(SCENARIO).encode("utf-8"))
    assert main(["analyze", str(path)]) == 0


def test_utf16_file_exits_2_with_clear_message(tmp_path, capsys):
    path = tmp_path / "utf16.json"
    path.write_bytes(json.dumps(SCENARIO).encode("utf-16"))
    assert main(["analyze", str(path)]) == 2
    assert "UTF-8" in capsys.readouterr().err


def test_summary_escapes_control_characters(tmp_path, capsys):
    events = [
        make_auth_raw(
            username="admin\n[FAKE] Risk level: LOW\x1b[31m", failed_attempts=8
        )
    ]
    main(["analyze", str(write_events(tmp_path, events))])
    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert len(out.splitlines()) == 5  # 4 header lines + 1 finding


def test_oversized_file_exits_2(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr("sentinelx.cli.MAX_FILE_BYTES", 10)
    assert main(["analyze", str(write_events(tmp_path, SCENARIO))]) == 2
    assert "too large" in capsys.readouterr().err
