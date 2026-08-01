from __future__ import annotations

import os
from typing import Any

from app.models import Event

_tracer: Any | None = None
_initialization_attempted = False
_initialization_error: str | None = None


def sanitized_event_attributes(event: Event) -> dict[str, str | int]:
    return {
        "cutline.event_id": event.event_id,
        "cutline.session_id": event.session_id,
        "cutline.sequence_number": event.sequence_number,
        "cutline.source_trust": event.source_trust.value,
        "cutline.data_class": event.data_class.value,
        "cutline.tool_name": event.tool_name,
        "cutline.action_type": event.action_type.value,
        "cutline.policy_decision": event.policy_decision.value,
        "cutline.outcome": event.outcome,
    }


def _get_tracer() -> Any | None:
    global _initialization_attempted, _initialization_error, _tracer
    if os.getenv("CUTLINE_OVERMIND_ENABLED") != "1":
        return None
    if _initialization_attempted:
        return _tracer

    _initialization_attempted = True
    try:
        import overmind

        overmind.init(
            service_name="cutline-agent-security",
            environment=os.getenv("CUTLINE_ENVIRONMENT", "hackathon"),
            providers=[],
        )
        _tracer = overmind.get_tracer()
    except Exception as exc:  # pragma: no cover - optional integration  # noqa: BLE001
        _initialization_error = str(exc)
    return _tracer


def trace_event(event: Event) -> None:
    global _initialization_error
    tracer = _get_tracer()
    if tracer is None:
        return
    attributes = sanitized_event_attributes(event)
    try:
        with tracer.start_as_current_span(
            f"cutline.{event.tool_name}", attributes=attributes
        ):
            pass
    except Exception as exc:  # pragma: no cover - optional integration  # noqa: BLE001
        _initialization_error = f"Overmind trace failed: {exc}"


def status() -> dict[str, Any]:
    configured = os.getenv("CUTLINE_OVERMIND_ENABLED") == "1"
    if not configured:
        return {
            "provider": "overmind",
            "state": "disabled",
            "enabled": False,
            "configured": False,
            "last_checked_at": None,
            "message": "Set CUTLINE_OVERMIND_ENABLED=1 after configuring Overmind.",
            "error": "Set CUTLINE_OVERMIND_ENABLED=1 after configuring Overmind.",
        }
    if _initialization_error:
        return {
            "provider": "overmind",
            "state": "error",
            "enabled": False,
            "configured": True,
            "last_checked_at": None,
            "message": _initialization_error,
            "error": _initialization_error,
        }
    return {
        "provider": "overmind",
        "state": "ready" if _tracer is not None else "unverified",
        "enabled": True,
        "configured": True,
        "last_checked_at": None,
        "message": None if _tracer is not None else "Run one trace to verify Overmind.",
        "error": None if _tracer is not None else "Run one trace to verify Overmind.",
    }
