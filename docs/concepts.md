# SentinelX Core — Concepts (my own words)
## Design notes (write these as I build)
- **Why timezone-aware timestamps?**
A timestamp without a timezone is ambiguous: it does not tell me which local time zone it belongs to. That can put events in the wrong order or make time-window calculations unreliable. Pydantic's AwareDatetime accepts any valid timezone offset, not just UTC, so I should convert timestamps to UTC before storing them. That gives SentinelX and later ForensiQ one consistent representation for sorting, comparing and replaying events
- **What does `extra="forbid"` protect against?**
It rejects fields that are not defined by the event model. For example, a typo such as faild_attempts should raise a validation error instead of being ignored and causing a detection to miss the event. The trade-off is that if a log source adds a legitimate field next month, parsing will fail until I update the model or deliberately support that field. That is acceptable for a controlled Week 1 model because it makes schema changes visible, but a real ingestion pipeline would need versioning or an explicit compatibility strategy.
- **Why one class per event type?**
Because different security events contain different information and have different validation requirements.It involves a little more code but each event is fully validated and works by AuthenticationEvent and ProcessExecutionEvent, chosen by event_type.
- **Why not use metadata?**
Because metadata is not validated against a strict schema, detection rules should not depend on values stored there. Values that affect detection—such as failed_attempts, privileged or command—belong in typed, validated fields. Metadata should be reserved for extra context that the rules do not need to make their decisions.

A useful scratch experiment is:
parse_event(make_auth_raw(failed_attempts="8"))
With Pydantic's default non-strict validation, the numeric string "8" is expected to be converted to the integer 8. A value such as "eight" should fail validation. That demonstrates that a typed field is parsed and checked according to its declared type; a value inside an unvalidated metadata dictionary does not automatically receive the same guarantees.
- **Why is a rule a pure function of the event?**
Each rule is a pure function: def failed_logins(event) -> Finding | None. 
It checks the event type, applies a named constant (FAILED_LOGIN_THRESHOLD = 5), and returns None for anything it doesn’t apply to
- **Noise in my rules** (where might a rule fire when it shouldn't?)
Noise is activity that legitimately matches a rule even though it does not represent the threat I am trying to identify. I should record a realistic noise case for each rule and then decide what extra context would reduce it.
- Rule 1 — Multiple failed logins: A user may mistype a password several times. The current event records failed_attempts and one timestamp, but it does not record the time window in which the failures occurred. Five failures in a minute and five failures spread across a month therefore look the same to this rule.
- Rule 2 — Privileged account activity:Rule 2 fires on every privileged login, including ordinary admin work.Rule is Privileged, if positive -privileged =True fires and if negative- privileged=False doesnt
- Rule 3 — Suspicious command execution: A legitimate command or executable named curly.exe could be flagged if the rule searches for the substring curl. Matching whole tokens or more precise command patterns could reduce this noise.
These are known limitations of the simple Week 1 rules, not reasons to add hidden complexity before the basic behavior is tested.

## Week 1 checkpoint questions
1. What is a security event? (Give a SentinelX example.)
A security event is a recorded observation about activity in a system; it does not automatically mean an attack has happened. For example, an AuthenticationEvent can record a username, source IP, timestamp and failed_attempts count. If it records failed_attempts=8, SentinelX knows that eight failures were reported, but that alone does not prove the account was compromised. The event supplies evidence for rules to evaluate.

2. What is the difference between an event and a detection rule?
An event is the data describing something that happened, while a detection rule is the logic used to decide whether that data matches a suspicious pattern.

For example, the event could record eight failed login attempts against an account. The detection rule could check whether the number of failed attempts meets a defined threshold. The event provides the evidence; the rule evaluates it.
3. Why should detection rules be separate from the engine?
Detection rules should be separate from the engine because the engine should handle the general processing workflow, while individual rules should focus on identifying specific suspicious behaviours.

This separation makes SentinelX easier to maintain and extend. I can add, modify, or test a rule without rewriting the entire engine. It also allows the same engine to run different rules against different event types.
4. Why should the Week 1 risk score be deterministic?
Deterministic means that the same findings and scoring configuration always produce the same score and risk level. If an alert scored 62 on Monday and 48 on Tuesday without any relevant input or configuration change, analysts would have less reason to trust the result, tests would become unreliable, and an auditor could not reproduce why an incident was escalated. With deterministic scoring, I can write an assertion such as assert score == 95 and know exactly what behavior the test is checking. When an LLM is introduced later, it may help explain an incident, but the core detection, scoring and risk-level calculation should remain deterministic so that the decision can be reproduced and audited.
5. What is the difference between a detection and a risk score?
A detection indicates that an event or group of events matched a defined suspicious pattern. A risk score estimates the level of concern associated with that event or detection.

For example, a rule might detect repeated failed logins and generate an alert. The risk-scoring component might then assign the alert a score of 80 out of 100 based on the number of attempts and other defined factors.

A detection answers, "Did this activity match a rule?" A risk score answers, "How concerning is this activity according to our scoring method?"
6. Why are we not adding an AI model yet?
I first need a reliable and testable foundation. If the event validation, detection rules, and risk-scoring logic are incorrect, adding AI would make the system more complicated without necessarily making it more accurate.
7. Why are we testing the engine before adding the web layer?
To verify that the core security logic works independently of the API. If something goes wrong later, I will be able to distinguish problems in the detection engine from problems in HTTP requests, authentication, or database integration.

Testing the engine first also helps me catch edge cases early, confirm that risk scores are consistent, and prevent incorrect detections from being exposed through the API. This gives SentinelX a more reliable foundation as I add more components.

**ruff check** - Asks "Is the code free of mistakes and untidy imports?"
**ruff format** - Asks "Is the style consistent?" 
**pytest** - Asks "Does the behaviour still work?"
pre-commit only runs the two Ruff checks, because they take under a second.

8. An event model should represent observations, not conclusions. The source of an event cannot automatically be trusted because it may be compromised, misconfigured, or manipulated. If the source can label an event as suspicious, an attacker could set the value to false to hide malicious activity or set it to true to flood analysts with false positives.
My own model illustrates the distinction. The privileged field represents a fact about the account: whether it has privileged access. A suspicious field would represent a verdict about the activity, which should be determined by detection rules rather than supplied by the event source.
Keeping observations separate from verdicts also makes the system easier to maintain. For example, if I change the failed-login threshold from 5 to 10, I should update the detection rule, not the event model. Because events contain observations rather than precomputed verdicts, I can reprocess historical events under the updated rules.
There is an important limitation: validation checks the structure and types of incoming data, not whether the information is truthful. A compromised source could also falsify failed_attempts, privileged, or other fields. Correlating observations across independent sources would eventually provide stronger context and help identify inconsistencies.
The principle is: events contain observations; rules decide what those observations mean.

9. A pure function is a function whose output depends only on its explicit inputs and which produces no side effects. Given the same input, it always returns the same output.

My `failed_logins` rule follows this principle. It evaluates the event data without accessing the system clock, a database, a network connection, global state, or randomness. This makes its behaviour predictable and easy to test.

Consider a rule that uses `datetime.now()` to determine whether an event occurred during business hours. Its result would depend on when the test runs, rather than only on the event being analysed. To test both branches of a condition such as `9 <= hour < 17`, I would have to run tests at different times of day or duplicate the business-hours logic inside the test. The first approach makes tests time-dependent; the second risks testing a copy of the implementation rather than the implementation itself.

A cleaner design is to pass the time explicitly, for example through `is_business_hours(now)`. The function can then evaluate a supplied datetime without depending on the system clock. This is preferable to mocking `datetime.now()`, because mocking patches an external dependency rather than removing that dependency from the function.

This principle also matters for SentinelX. Events already contain a `timestamp`, so future time-window rules should use the event timestamp rather than `datetime.now()`. That means replaying last week's events next month can produce the same findings, which will be important for ForensiQ.

It has also made testing simpler: my 19 rule tests require no mocks, need no setup beyond helpers such as `make_auth_raw`, and finish in milliseconds.