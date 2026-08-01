from __future__ import annotations

from dataclasses import dataclass, field
from itertools import count
from typing import Any
from uuid import uuid4

from app.models import (
    ActionType,
    DataClass,
    Event,
    PolicyDecision,
    TrustLevel,
)


@dataclass
class EventRecorder:
    session_id: str
    events: list[Event] = field(default_factory=list)
    _sequence: Any = field(default_factory=lambda: count(1), init=False)

    def emit(
        self,
        *,
        actor: str,
        source_type: str,
        source_trust: TrustLevel,
        data_class: DataClass,
        tool_name: str,
        action_type: ActionType,
        outcome: str,
        message: str,
        parent_event_id: str | None = None,
        resource: str | None = None,
        destination: str | None = None,
        arguments_redacted: dict[str, Any] | None = None,
        policy_decision: PolicyDecision = PolicyDecision.NOT_EVALUATED,
    ) -> Event:
        event = Event(
            event_id=f"evt_{uuid4().hex[:8]}",
            session_id=self.session_id,
            parent_event_id=parent_event_id,
            sequence_number=next(self._sequence),
            actor=actor,
            source_type=source_type,
            source_trust=source_trust,
            data_class=data_class,
            tool_name=tool_name,
            resource=resource,
            destination=destination,
            action_type=action_type,
            arguments_redacted=arguments_redacted or {},
            policy_decision=policy_decision,
            outcome=outcome,
            message=message,
        )
        self.events.append(event)
        return event
