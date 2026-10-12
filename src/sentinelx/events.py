from typing import Annotated, Any, Literal
from uuid import uuid4

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    TypeAdapter,
)


class BaseEvent(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: AwareDatetime
    source: str = Field(min_length=1)
    username: str = Field(min_length=1, max_length=256)
    source_ip: IPvAnyAddress | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class AuthenticationEvent(BaseEvent):
    event_type: Literal["authentication"]
    failed_attempts: int = Field(default=0, ge=0)
    privileged: bool = False


class ProcessExecutionEvent(BaseEvent):
    event_type: Literal["process_execution"]
    command: str = Field(min_length=1, max_length=8192)


SecurityEvent = Annotated[
    AuthenticationEvent | ProcessExecutionEvent,
    Field(discriminator="event_type"),
]
_adapter = TypeAdapter(SecurityEvent)


def parse_event(raw: dict[str, Any]) -> AuthenticationEvent | ProcessExecutionEvent:
    return _adapter.validate_python(raw)
