from __future__ import annotations

from collections.abc import Iterable

from app.models import ActionType, DataClass, Event, Incident, TrustLevel


def find_attack_chain(events: Iterable[Event]) -> tuple[Event, Event, Event]:
    ordered = sorted(events, key=lambda event: event.sequence_number)
    instruction = next(
        (
            event
            for event in ordered
            if event.source_trust == TrustLevel.UNTRUSTED
            and event.tool_name == "read_workspace_rule"
        ),
        None,
    )
    secret_read = next(
        (
            event
            for event in ordered
            if instruction
            and event.session_id == instruction.session_id
            and event.parent_event_id == instruction.event_id
            and event.sequence_number > instruction.sequence_number
            and event.data_class == DataClass.SECRET
            and event.action_type == ActionType.READ
        ),
        None,
    )
    external_write = next(
        (
            event
            for event in ordered
            if secret_read
            and event.session_id == secret_read.session_id
            and event.parent_event_id == secret_read.event_id
            and event.sequence_number > secret_read.sequence_number
            and event.action_type == ActionType.EXTERNAL_WRITE
        ),
        None,
    )
    if not instruction or not secret_read or not external_write:
        raise ValueError(
            "Cannot generate the guardrail because the required evidence path is incomplete."
        )
    return instruction, secret_read, external_write


def build_incident(events: Iterable[Event]) -> Incident:
    instruction, secret_read, external_write = find_attack_chain(events)
    return Incident(
        incident_id=f"incident_{instruction.session_id}",
        source_session_id=instruction.session_id,
        severity="high",
        summary=(
            "Synthetic secret flowed from an untrusted workspace rule into an "
            "unauthorized external write."
        ),
        evidence_event_ids=[
            instruction.event_id,
            secret_read.event_id,
            external_write.event_id,
        ],
        attack_path_verified=True,
    )
