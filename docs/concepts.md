# SentinelX Core — Concepts (my own words)
## Design notes (write these as I build)
- **Why timezone-aware timestamps?**
timelines in SentinelX and later ForensiQ break if some events carry local time and others UTC. timezone-aware timestamps are used because security events can come from systems in different countries or time zones. If I use timestamps without time zone information, it can be difficult to determine the actual order of events during an investigation. Using timezone-aware timestamps, preferably normalized to UTC, makes it easier to correlate events accurately and build reliable incident timelines.
- **What does `extra="forbid"` protect against?**
extra="forbid" prevents my data model from accepting fields that I haven't explicitly defined. For example,setting extra="forbid", so a typo like faild_attempts is rejected loudly and doesn’t default to 0(silent miss). It helps catch malformed data, spelling mistakes, and unexpected input early, making the engine more predictable.
- **Why one class per event type?**
Because different security events contain different information and have different validation requirements.It involves a little more code but each event is fully validated and works by AuthenticationEvent and ProcessExecutionEvent, chosen by event_type.
- **Why not use metadata?**
becaise nothing validates metadata, Its only for extra context that no rule reads. A source that sends "8" or misspells the key makes the rule silently miss. In security tooling, the dangerous failure is a silent miss: a detection that quietly stops working because of bad input, which is worse than a crash.
- **Why is a rule a pure function of the event?**
Each rule is a pure function: def failed_logins(event) -> Finding | None. 
It checks the event type, applies a named constant (FAILED_LOGIN_THRESHOLD = 5), and returns None for anything it doesn’t apply to
- **Noise in my rules** (where might a rule fire when it shouldn't?)
1.Rule 2 fires on every privileged login, including ordinary admin work.Rule is Privileged, if positive -privileged =True fires and if negative- privileged=False doesnt
2.Simple substring matching on curl would flag curly.exe.
## Week 1 checkpoint questions
1. What is a security event? (Give a SentinelX example.)
A security event is a recorded activity or observation from a system that may be relevant to security monitoring or investigation. An event does not automatically mean that an attack has occurred; it is information that the engine can evaluate.

For example, SentinelX might receive an event showing that the account admin had eight failed login attempts from the IP address 10.0.0.12 within a short period. SentinelX can use that event to check whether the activity matches a suspicious pattern.
2. What is the difference between an event and a detection rule?
An event is the data describing something that happened, while a detection rule is the logic used to decide whether that data matches a suspicious pattern.

For example, the event could record eight failed login attempts against an account. The detection rule could check whether the number of failed attempts meets a defined threshold. The event provides the evidence; the rule evaluates it.
3. Why should detection rules be separate from the engine?
Detection rules should be separate from the engine because the engine should handle the general processing workflow, while individual rules should focus on identifying specific suspicious behaviours.

This separation makes SentinelX easier to maintain and extend. I can add, modify, or test a rule without rewriting the entire engine. It also allows the same engine to run different rules against different event types.
4. Why should the Week 1 risk score be deterministic?
5. What is the difference between a detection and a risk score?
A detection indicates that an event or group of events matched a defined suspicious pattern. A risk score estimates the level of concern associated with that event or detection.

For example, a rule might detect repeated failed logins and generate an alert. The risk-scoring component might then assign the alert a score of 80 out of 100 based on the number of attempts and other defined factors.

A detection answers, "Did this activity match a rule?" A risk score answers, "How concerning is this activity according to our scoring method?"
6. Why are we not adding an AI model yet?
I first need a reliable and testable foundation. If the event validation, detection rules, and risk-scoring logic are incorrect, adding AI would make the system more complicated without necessarily making it more accurate.
7. Why are we testing the engine before adding the web layer?
To verify that the core security logic works independently of the API. If something goes wrong later, I will be able to distinguish problems in the detection engine from problems in HTTP requests, authentication, or database integration.

Testing the engine first also helps me catch edge cases early, confirm that risk scores are consistent, and prevent incorrect detections from being exposed through the API. This gives SentinelX a more reliable foundation as I add more components.
8. Why does the event model contain no notion of “suspicious”? (Event versus rule.)
9. Why is a rule a pure function of the event, with no database, clock or network? What does that make easier to test?

Your three rules (failed logins, privileged activity, suspicious command) are a good set, and process_execution adds variety to the event types. Your scoring means only all three findings together reach CRITICAL, since any two top out at 70 (HIGH).
**ruff check** - Asks "Is the code free of mistakes and untidy imports?"
**ruff format** - Asks "Is the style consistent?" 
**pytest** - Asks "Does the behaviour still work?"
pre-commit only runs the two Ruff checks, because they take under a second.