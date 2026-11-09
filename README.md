# SentinelX Core

SentinelX Core is a deterministic security-event detection and risk-scoring engine built to analyse structured security events, identify potentially suspicious activity, and assign risk scores based on predefined detection rules.

It analyses authentication and process-execution events to identify patterns such as repeated failed login attempts, privileged account activity, and potentially suspicious command execution.

The project is a learning and portfolio project focused on deterministic security-event detection and risk scoring.

SentinelX Core is not an AI model. It is a deterministic detection and scoring engine. Given the same validated events and rules, it produces reproducible findings and risk assessments. Its detection and scoring decisions do not depend on an LLM.

## Quick start
Requires uv.

    git clone https://github.com/tnzisa/sentinelx-core
    cd sentinelx-core
    uv sync
    uv run python -m sentinelx analyze examples/events.json
## Example output
Events analyzed: 2
Risk score: 95
Risk level: CRITICAL
Findings: 3
    - [failed_logins] Multiple failed logins: 8 failed attempts for admin
    - [privileged_activity] Privileged account activity: Privileged account admin logged in from 10.0.0.25 
    - [suspicious_command] Suspicious command execution: Command by admin matched: encoded PowerShell

The analysis also emits a structured analysis_complete log record to standard error.

A successful analysis exits with code 0.
## How it works
SentinelX processes validated security events through independent detection and scoring stages.

`` ```text ``
             SECURITY EVENTS
                    |
                    v
             EVENT VALIDATION
                    |
                    v
              DETECTION RULES
                    |
          +---------+---------+
          |         |         |
          v         v         v
      Failed    Privileged  Suspicious
      Logins    Activity    Command
          |         |         |
          +---------+---------+
                    |
                    v
                 FINDINGS
                    |
                    v
              RISK SCORING
                    |
                    v
               RISK LEVEL
                    |
                    v
             ANALYSIS RESULT
`` ``` ``
**Events:** Structured authentication and process-execution events are supplied as input.
**Validation:** Input is checked against the expected event models and field types.
**Rules:** Each validated event is evaluated against the registered detection rules.
**Findings:** Matching rules produce structured findings with evidence.
**Score:** Finding weights contribute to the overall risk score. Each detection rule contributes its configured weight only once per analysis,
regardless of how many findings that rule produces. Findings are preserved
individually, while the total risk score is capped at 100.
**Risk Level:** The final score is mapped to a risk category.

The engine applies its rules in a fixed order and preserves repeated findings. Its analysis results are immutable, supporting reproducible analysis.

## Input format
SentinelX accepts a UTF-8 encoded JSON file containing a list of security events. UTF-8 files with a byte-order mark (BOM) are also supported. The maximum input file size is **10 MiB (10,485,760 bytes)**.

Each event must match one of the supported event types. Unknown fields are rejected.

| Field | Applies to | Required | Rules |
|---|---|---|---|
| `event_type` | Both | Yes | `"authentication"` or `"process_execution"` |
| `timestamp` | Both | Yes | ISO 8601 timestamp with a timezone |
| `source` | Both | Yes | Non-empty string |
| `username` | Both | Yes | String, 1–256 characters |
| `source_ip` | Both | No | IPv4 or IPv6 address; `null` is accepted |
| `event_id` | Both | No | String; generated automatically when omitted |
| `metadata` | Both | No | Dictionary; defaults to `{}` and is not used by detection rules |
| `failed_attempts` | Authentication | No | Integer ≥ 0; defaults to `0` |
| `privileged` | Authentication | No | Boolean; defaults to `false` |
| `command` | Process execution | Yes | String, 1–8192 characters |

### Example input

```json
[
  {
    "event_type": "authentication",
    "timestamp": "2026-11-09T08:30:00Z",
    "source": "auth-server-01",
    "username": "admin",
    "failed_attempts": 8,
    "privileged": true
  },
  {
    "event_type": "process_execution",
    "timestamp": "2026-11-09T08:35:00+03:00",
    "source": "endpoint-01",
    "username": "analyst",
    "command": "powershell.exe -EncodedCommand ..."
  }
]
```

Event validation errors identify the event index, affected field, and validation error type without echoing the rejected field value.

## Rules
| Rule | Detects | Weight | Known noise |
|---|---|---|---|

| failed_logins | 5 or more failed attempts | 30 | Legitimate password mistakes can trigger the rule. The current event model does not establish a time window for the failures |

| privileged_activity | privileged account login | 25 | Legitimate administrative access and scheduled maintenance can trigger the rule.|

| suspicious_command | encoded PowerShell, curl, wget | 40 | Legitimate command execution can match broad indicators. For example, substring matching could flag an executable named curly.exe |

## Risk levels
| Score | Level |
|---|---|
| 0–29 | LOW |
| 30–59 | MEDIUM |
| 60–79 | HIGH |
| 80–100 | CRITICAL |

### Risk scoring
Each detection rule contributes its configured weight only once per analysis, regardless of how many findings it produces. Individual findings are preserved, but scoring uses unique rule IDs. The total score is capped at 100.

| Detection rule | Weight |
|---|---:|
| `failed_logins` | 30 |
| `privileged_activity` | 25 |
| `suspicious_command` | 40 |

For example, ten `failed_logins` findings still contribute 30 points, not 300. If all three rules produce findings, their combined score is 95.

Risk levels:

- **LOW:** 0–29
- **MEDIUM:** 30–59
- **HIGH:** 60–79
- **CRITICAL:** 80–100

Unknown rule IDs raise a `ValueError` rather than silently contributing zero points.

## Design decisions
Event validation: Events are validated against typed, event-specific models before analysis. This prevents rules from operating on malformed or incorrectly structured data.

Deterministic scoring: Detection and scoring are rule-based and reproducible. The same input produces the same findings and risk assessment, making results easier to test, audit, and investigate.

Unknown rules fail loudly: Rule identifiers must resolve to known detection rules. Unknown identifiers raise an error rather than being silently ignored or treated as a successful analysis.

Malformed input is rejected as a whole: Invalid input is not partially analysed. This prevents incomplete or unreliable data from silently producing a risk assessment.

Output sanitization: Error and validation details are presented at the CLI boundary without exposing raw input values. Analysis results are printed to stdout; structured diagnostic logs are written to stderr.

### Output
SentinelX separates analysis results from diagnostic logging:

- **Standard output (stdout):** Human-readable analysis summary, including event count, risk score, risk level, and findings.
- **Standard error (stderr):** Structured JSON diagnostic logs containing the analysis event, timestamp, severity, and summary fields.

## Exit codes
| Code | Meaning |
|---|---|
| 0 | Analysis completed |
| 2 | Invalid input or usage |

## Development
    uv run pytest - runs automated tests
    uv run ruff check . - runs lint checks
    uv run ruff format --check . -checks formatting
    uv run pre-commit install -installs Git pre-commit hooks

## Limitations and roadmap
Current limitations

- No time-window-based detection.
- No persistent event storage.
- No API interface.
- Pattern-based command detection may produce false positives.
- Privileged-account detection depends on the accuracy of supplied event data.

Planned improvements

- Time-window-based detection.
- Additional detection rules.
- API integration.
- Further security-event correlation.
- Expanded detection and scoring test coverage.