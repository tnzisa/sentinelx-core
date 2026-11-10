# SentinelX Core — Concepts (my own words)

## Design notes

### Why timezone-aware timestamps?

A timestamp without a timezone is ambiguous: it does not tell me which local time zone it belongs to. That can put events in the wrong order or make time-window calculations unreliable. Pydantic's `AwareDatetime` accepts valid timezone offsets, not just UTC. I should convert timestamps to UTC before storing them so SentinelX and later ForensiQ have one consistent representation for sorting, comparing and replaying events.

### What does `extra="forbid"` protect against?

It rejects fields that are not defined by the event model. For example, a typo such as `faild_attempts` raises a validation error instead of being ignored and potentially causing a detection to miss the event.

The trade-off is that if a log source adds a legitimate field, parsing will fail until I update the model or deliberately support that field. That is acceptable for a controlled Week 1 model because it makes schema changes visible. A real ingestion pipeline would need versioning or an explicit compatibility strategy.

### Why one class per event type?

Different security events contain different information and have different validation requirements. `AuthenticationEvent` contains fields such as `failed_attempts` and `privileged`, while `ProcessExecutionEvent` contains `command`.

The separate models prevent fields from one event type from being accepted on another. For example, `test_process_event_cannot_carry_authentication_fields` verifies that a process-execution event containing `failed_attempts` is rejected with an `extra_forbidden` validation error.

This means rules can rely on the fields appropriate to each event type instead of handling irrelevant or incorrectly structured fields.

### Why not use metadata?

Metadata is not validated against a strict schema, so detection rules should not depend on values stored there. Values that affect detection—such as `failed_attempts`, `privileged` or `command`—belong in typed, validated fields. Metadata should be reserved for additional context that rules do not need to make their decisions.

A useful scratch experiment is:

```python
parse_event(make_auth_raw(failed_attempts="8"))
parse_event(make_auth_raw(failed_attempts="eight"))
```

With the current Pydantic validation behaviour, `"8"` is converted to the integer `8`. The value `"eight"` raises a `ValidationError` with the error type `int_parsing`.

This demonstrates that typed fields are parsed and checked according to their declared types. A value inside an unvalidated metadata dictionary does not automatically receive the same guarantees.

### Why is a rule a pure function of the event?

A pure function depends only on its explicit inputs, produces no side effects, and returns the same output for the same input.

My `failed_logins` rule follows this principle. It checks the event type, applies the named constant `FAILED_LOGIN_THRESHOLD = 5`, and returns either a `Finding` or `None`. It does not access the system clock, a database, a network connection, global state or randomness.

Consider a rule that uses `datetime.now()` to decide whether an event occurred during business hours. Its result would depend on when the test runs rather than only on the event being analysed. To test both branches of `9 <= hour < 17`, I would need to run tests at different times of day or duplicate the business-hours logic inside the test. The first makes tests time-dependent; the second risks testing a copy of the implementation instead of the implementation itself.

A cleaner design is to pass the time explicitly, for example through `is_business_hours(now)`. The function can then evaluate a supplied datetime without depending on the system clock. This is preferable to mocking `datetime.now()`, because mocking patches an external dependency instead of removing that dependency from the function.

This also matters for SentinelX. Events already carry a `timestamp`, so future time-window rules should use the event timestamp, never `datetime.now()`. Replaying last week's events next month should produce the same detection decisions. Generated event IDs can still differ if the original events did not supply IDs, so stable references require supplied `event_id` values. This will matter for ForensiQ.

The design has made testing simpler: `tests/test_rules.py` contains 20 rule test cases, including parametrized cases. They need no mocks and use helpers such as `make_auth_raw` to prepare inputs.

### Noise in my rules

Noise is activity that legitimately matches a rule even though it does not represent the threat I am trying to identify. I should record a realistic noise case for each rule and consider what additional context could reduce it.

- **Rule 1 — Multiple failed logins:** A user may mistype a password several times. The current event records `failed_attempts` and one timestamp, but it does not establish a time window for the failures. Five failures in a minute and five failures spread across a month therefore look the same to this rule.

- **Rule 2 — Privileged account activity:** The rule fires every time it receives an authentication event with `privileged=True`. Legitimate administrator logins and scheduled maintenance can therefore trigger it. I cannot say how often this happens without analysing actual event data.

- **Rule 3 — Suspicious command execution:** `curl` and `wget` are everyday tools for administrators and developers, and legitimate management software can use encoded PowerShell. Whole-word matching avoids false matches such as `curly.exe`, but a filename such as `curl-notes.txt` can still match because the hyphen creates a word boundary. A match is an indicator for investigation, not proof of malicious activity.

These are known limitations of the simple Week 1 rules, not reasons to add hidden complexity before the basic behaviour is tested.

### Why do events carry no verdicts?

An event model should represent observations, not conclusions. The source of an event cannot automatically be trusted because it may be compromised, misconfigured or manipulated. If the source can label an event as suspicious, an attacker could set the value to `false` to hide malicious activity or set it to `true` to flood analysts with false positives.

My own model illustrates the distinction. The `privileged` field represents an account attribute: whether the account has privileged access. A `suspicious` field would represent a verdict about the activity, which should be determined by detection rules rather than supplied by the event source.

Keeping observations separate from verdicts also makes the system easier to maintain. If I change the failed-login threshold from 5 to 10, I should update the detection rule, not the event model. Because events hold observations rather than precomputed verdicts, I can reprocess historical events under the updated rules.

There is an important limitation: validation checks the structure and types of incoming data, not whether the information is truthful. A compromised source could also falsify `failed_attempts`, `privileged` or other fields. Correlating observations across independent sources would eventually provide stronger context and help identify inconsistencies.

The principle is: **events contain observations; rules decide what those observations mean.**

## Week 1 checkpoint questions

### 1. What is a security event? (Give a SentinelX example.)

A security event is a recorded observation about activity in a system; it does not automatically mean an attack has happened. For example, an `AuthenticationEvent` can record a username, source IP, timestamp and `failed_attempts` count. If it records `failed_attempts=8`, SentinelX knows that eight failures were reported, but that alone does not prove the account was compromised. The event supplies evidence for rules to evaluate.

### 2. What is the difference between an event and a detection rule?

An event is the data describing something that happened, while a detection rule is the logic used to decide whether that data matches a suspicious pattern.

For example, an event could record eight failed login attempts against an account. The detection rule checks whether the number of failed attempts meets a defined threshold. The event provides the evidence; the rule evaluates it.

### 3. Why should detection rules be separate from the engine?

Detection rules should be separate from the engine because the engine should handle the general processing workflow, while individual rules should focus on identifying specific suspicious behaviours.

This separation makes SentinelX easier to maintain and extend. I can add, modify or test a rule without rewriting the entire engine. It also allows the same engine to run different rules against different event types.

For example, `failed_logins` has three tests that call the rule directly, without involving the engine. This lets me test the rule's behaviour independently.

### 4. Why should the Week 1 risk score be deterministic?

Deterministic means that the same findings and scoring configuration produce the same score and risk level. If an alert scored 62 on Monday and 48 on Tuesday without any relevant input or configuration change, analysts would have less reason to trust the result, tests would become unreliable, and an auditor could not reproduce why an incident was escalated.

With deterministic scoring, I can write an assertion such as `assert score == 95` and know exactly what behaviour the test is checking. The score, risk level and rule IDs repeat exactly for the same inputs and configuration; only generated event IDs differ when they were not supplied.

When an LLM is introduced later, it may help explain an incident, but the core detection, scoring and risk-level calculation should remain deterministic so that the decision can be reproduced and audited.

### 5. What is the difference between a detection and a risk score?

A detection indicates that an event or group of events matched a defined suspicious pattern. A risk score estimates the level of concern associated with the findings produced by those detections.

For example, `failed_logins` detects five or more failed attempts and produces a finding. The scoring component then adds the configured weight for that rule: 30 points. The other rules contribute 25 points for `privileged_activity` and 40 points for `suspicious_command`. Each distinct rule contributes its weight only once per analysis, and the total score is capped at 100.

This means five failed attempts and 500 failed attempts currently contribute the same 30 points if they produce the same `failed_logins` rule finding. The number of attempts appears in the finding evidence, but it does not change the score.

To make attempt volume affect risk, I could introduce graduated severity based on the number of attempts. The detection logic could identify the severity, while the scoring component translates that severity into points. This is a useful improvement for a later iteration because the current scoring model uses fixed weights per rule.

A detection answers, "Did this activity match a rule?" A risk score answers, "How concerning are the resulting findings according to my scoring method?"

### 6. Why are we not adding an AI model yet?

I first need a reliable and testable foundation. This week, an LLM could help explain findings in natural language, but it would not solve a problem that the current detection and scoring engine cannot already handle deterministically. Adding it now would increase complexity before the core behaviour is established.

In Week 8, I can compare the AI's explanations and triage suggestions against SentinelX's deterministic findings, rule IDs and scores, as well as labelled test scenarios with known expected outcomes. The deterministic engine provides a consistent reference for the system's expected behaviour; it does not automatically prove that every real-world detection is correct.

### 7. Why are we testing the engine before adding the web layer?

I need to verify that the core security logic works independently of the API. If something goes wrong later, I will be able to distinguish problems in the detection engine from problems in HTTP requests, authentication or database integration.

Testing the engine first also helps me catch edge cases early, confirm that risk scores are consistent and prevent incorrect detections from being exposed through the API. This gives SentinelX a more reliable foundation as I add more components.

## Tooling notes

- `uv run ruff check .` checks the code for lint issues, including common errors and import problems.
- `uv run ruff format --check .` checks whether the code follows the expected formatting without changing files.
- `uv run pytest` runs the test suite to check that the expected behaviour still works.
- `uv run pytest tests/test_rules.py -q` runs only the detection-rule tests.
- `pre-commit` runs the configured Ruff checks automatically before a commit.