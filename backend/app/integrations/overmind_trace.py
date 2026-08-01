from __future__ import annotations

import os
from datetime import UTC, datetime
from importlib import import_module
from typing import Any

from app.integrations.safe_projection import SafeEvent, SafeRun, SafeToolCategory

_sdk: Any | None = None
_initialized = False
_state = "unverified"
_last_checked_at: datetime | None = None
_message: str | None = None

_EVENT_NAMES = {
    SafeToolCategory.TASK: "task",
    SafeToolCategory.INSTRUCTION_READ: "instruction-read",
    SafeToolCategory.FILE_READ: "file-read",
    SafeToolCategory.EXTERNAL_WRITE: "external-write",
    SafeToolCategory.FILE_WRITE: "file-write",
    SafeToolCategory.TEST_RUN: "test-run",
    SafeToolCategory.UNKNOWN: "unknown",
}


def _configured() -> bool:
    return bool(os.getenv("OVERMIND_API_KEY"))


def _run_attributes(run: SafeRun) -> dict[str, str | bool | int]:
    return {
        "cutline.mode": run.mode.value,
        "cutline.provider": run.provider.value,
        "cutline.status": run.status.value,
        "cutline.secret_exposed": run.secret_exposed,
        "cutline.exfiltration_attempted": run.exfiltration_attempted,
        "cutline.exfiltration_blocked": run.exfiltration_blocked,
        "cutline.code_fixed": run.code_fixed,
        "cutline.tests_passed": run.tests_passed,
        "cutline.collector_count": run.collector_count,
    }


def _event_attributes(event: SafeEvent) -> dict[str, str | int]:
    return {
        "cutline.event_id": event.event_id,
        "cutline.parent_event_id": event.parent_event_id or "root",
        "cutline.sequence_number": event.sequence_number,
        "cutline.source_trust": event.source_trust.value,
        "cutline.data_class": event.data_class.value,
        "cutline.action_type": event.action_type.value,
        "cutline.policy_decision": event.policy_decision.value,
        "cutline.outcome": event.outcome.value,
    }


def _span_type(sdk: Any, category: SafeToolCategory) -> Any:
    if category in {
        SafeToolCategory.INSTRUCTION_READ,
        SafeToolCategory.FILE_READ,
    }:
        return sdk.SpanType.RETRIEVAL
    return sdk.SpanType.TOOL


def _initialize() -> Any:
    global _initialized, _sdk
    if _initialized and _sdk is not None:
        return _sdk
    sdk = import_module("overmind")
    sdk.init(
        overmind_api_key=os.environ["OVERMIND_API_KEY"],
        service_name="cutline-agent-security",
        environment="demo",
        providers=None,
        agent_id=os.getenv("OVERMIND_AGENT_ID"),
        agent_name="CUTLINE Replay Agent",
        project_id=os.getenv("OVERMIND_PROJECT_ID"),
    )
    _sdk = sdk
    _initialized = True
    return sdk


def trace_run(run: SafeRun) -> None:
    global _last_checked_at, _message, _state
    if os.getenv("CUTLINE_OVERMIND_ENABLED") != "1":
        return
    if not _configured():
        _state = "error"
        _message = "Overmind configuration is incomplete."
        return
    try:
        sdk = _initialize()
        with sdk.start_span(
            "cutline.run",
            span_type=sdk.SpanType.ENTRY_POINT,
            attributes=_run_attributes(run),
        ):
            with sdk.start_span(
                "cutline.fix-and-verify",
                span_type=sdk.SpanType.WORKFLOW,
                attributes={"cutline.event_count": len(run.events)},
            ):
                for event in run.events:
                    sdk_name = _EVENT_NAMES[event.tool_category]
                    with sdk.start_span(
                        f"cutline.event.{sdk_name}",
                        span_type=_span_type(sdk, event.tool_category),
                        attributes=_event_attributes(event),
                    ):
                        pass
        sdk.force_flush_traces(timeout_millis=1000)
    except Exception:  # noqa: BLE001 - optional telemetry cannot affect CUTLINE
        _state = "error"
        _message = "Overmind telemetry failed."
        return
    _last_checked_at = datetime.now(UTC)
    _state = "ready"
    _message = "Telemetry flush completed; provider ingestion remains unverified."


def status() -> dict[str, Any]:
    enabled = os.getenv("CUTLINE_OVERMIND_ENABLED") == "1"
    if not enabled:
        return {
            "provider": "overmind",
            "state": "disabled",
            "configured": False,
            "last_checked_at": None,
            "message": "Set CUTLINE_OVERMIND_ENABLED=1 after configuring Overmind.",
        }
    if not _configured():
        return {
            "provider": "overmind",
            "state": "error",
            "configured": False,
            "last_checked_at": None,
            "message": "Overmind configuration is incomplete.",
        }
    return {
        "provider": "overmind",
        "state": _state,
        "configured": True,
        "last_checked_at": _last_checked_at,
        "message": _message or "Run one trace to verify Overmind delivery.",
    }
