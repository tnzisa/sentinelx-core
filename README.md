# SentinelX Core

SentinelX Core is a deterministic security-event detection and risk-scoring engine built to analyse structured security events, identify potentially suspicious activity, and assign risk scores based on predefined detection rules.

It analyses authentication and process-execution events to identify patterns such as repeated failed login attempts, privileged account activity, and potentially suspicious command execution.

The project is intended for cybersecurity learners, security analysts, and developers interested in understanding how a rule-based security-event analysis pipeline works.

SentinelX Core is not an AI model. It is a deterministic detection and scoring engine. Given the same validated events and rules, it produces reproducible findings and risk assessments. Its detection and scoring decisions do not depend on an LLM.

## Quick start
Requires uv.

    git clone https://github.com/tnzisa/sentinelx-core
    cd sentinelx-core
    uv sync
    uv run python -m sentinelx analyze examples/events.json
## Example output
The following reflects the confirmed results from the example analysis run:

Events analyzed: 2
Risk score: 95
Risk level: CRITICAL
Findings: 3

[failed_logins]
8 failed attempts for admin

[privileged_activity]
Privileged account admin logged in from 10.0.0.25

[suspicious_command]
Command by admin matched: encoded PowerShell

The analysis also emits a structured analysis_complete log record to standard error.

A successful analysis exits with code 0.
## How it works
SentinelX Core follows a deterministic processing pipeline:

Security Events
      |
      v
Event Validation
      |
      v
Detection Rules
      |
      v
Findings
      |
      v
Risk Scoring
      |
      v
Risk Level

Events: Structured authentication and process-execution events are supplied as input.

Validation: Input is checked against the expected event models and field types.

Rules: Each validated event is evaluated against the registered detection rules.

Findings: Matching rules produce structured findings with evidence.

Score: Finding weights contribute to the overall risk score.

Risk Level: The final score is mapped to a risk category.

The engine applies its rules in a fixed order and preserves repeated findings. Its analysis results are immutable, supporting reproducible analysis.
## Rules
| Rule | Detects | Weight | Known noise |
|---|---|---|---|
| failed_logins | 5 or more failed attempts | 30 | <your note: no time window> |
| privileged_activity | privileged account login | 25 | <your note> |
| suspicious_command | encoded PowerShell, curl, wget | 40 | <your note> |

## Risk levels
| Score | Level |
|---|---|
| 0–29 | LOW |
| 30–59 | MEDIUM |
| 60–79 | HIGH |
| 80–100 | CRITICAL |

## Design decisions
Event validation: Events are validated against typed, event-specific models before analysis. This prevents rules from operating on malformed or incorrectly structured data.

Deterministic scoring: Detection and scoring are rule-based and reproducible. The same input produces the same findings and risk assessment, making results easier to test, audit, and investigate.

Unknown rules fail loudly: Rule identifiers must resolve to known detection rules. Unknown identifiers should produce an explicit error rather than being silently ignored or treated as a successful analysis.

Malformed input is rejected as a whole: Invalid input is not partially analysed. This prevents incomplete or unreliable data from silently producing a risk assessment.

Output sanitization: Error and validation details are presented at the CLI boundary without exposing raw input values. Internal diagnostic information is kept separate from user-facing output.

See docs/concepts.md for further details about the project's architecture and design decisions.

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

-No time-window-based detection.
-No persistent event storage.
-No API interface.
-Pattern-based command detection may produce false positives.
-Privileged-account detection depends on the accuracy of supplied event data.

Planned improvements

-Time-window-based detection.
-Additional detection rules.
-API integration.
-Further security-event correlation.
-Expanded detection and scoring test coverage.