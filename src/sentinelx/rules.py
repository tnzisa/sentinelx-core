import re

from pydantic import BaseModel, ConfigDict

from sentinelx.events import AuthenticationEvent, ProcessExecutionEvent

FAILED_LOGIN_THRESHOLD = 5


class Finding(BaseModel):
    model_config = ConfigDict(frozen=True)

    rule_id: str
    title: str
    event_id: str
    evidence: str


def failed_logins(
    event: AuthenticationEvent | ProcessExecutionEvent,
) -> Finding | None:
    if not isinstance(event, AuthenticationEvent):
        return None
    if event.failed_attempts < FAILED_LOGIN_THRESHOLD:
        return None
    return Finding(
        rule_id="failed_logins",
        title="Multiple failed logins",
        event_id=event.event_id,
        evidence=f"{event.failed_attempts} failed attempts for {event.username}",
    )


def privileged_activity(
    event: AuthenticationEvent | ProcessExecutionEvent,
) -> Finding | None:
    if not isinstance(event, AuthenticationEvent):
        return None
    if not event.privileged:
        return None

    ip_text = "unknown source" if event.source_ip is None else str(event.source_ip)

    return Finding(
        rule_id="privileged_activity",
        title="Privileged account activity",
        event_id=event.event_id,
        evidence=(f"Privileged account {event.username} logged in from {ip_text} "),
    )


SUSPICIOUS_COMMAND_PATTERNS = {
    "encoded PowerShell": re.compile(
        r"\b(?:powershell|pwsh)(?:\.exe)?\b.*\s-(?:e|ec|enc\w*)(?=\s|$)",
        re.IGNORECASE,
    ),
    "wget": re.compile(r"\bwget(?:\.exe)?\b", re.IGNORECASE),
    "curl": re.compile(r"\bcurl(?:\.exe)?\b", re.IGNORECASE),
}


def suspicious_command(
    event: AuthenticationEvent | ProcessExecutionEvent,
) -> Finding | None:
    if not isinstance(event, ProcessExecutionEvent):
        return None
    for name, pattern in SUSPICIOUS_COMMAND_PATTERNS.items():
        if pattern.search(event.command):
            return Finding(
                rule_id="suspicious_command",
                title="Suspicious command execution",
                event_id=event.event_id,
                evidence=f"Command by {event.username} matched: {name}",
            )
    return None
