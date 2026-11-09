import json
import os
import subprocess
import sys

from tests.helpers import make_auth_raw


def test_non_ascii_username_does_not_crash_on_ascii_stdout(tmp_path):
    path = tmp_path / "uni.json"
    path.write_text(json.dumps([make_auth_raw(username="Привет")]), encoding="utf-8")
    env = {**os.environ, "PYTHONIOENCODING": "ascii"}

    result = subprocess.run(
        [sys.executable, "-m", "sentinelx", "analyze", str(path)],
        capture_output=True,
        env=env,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr.decode("ascii", "replace")
    assert b"\\u041f" in result.stdout
    assert b"Traceback" not in result.stderr
