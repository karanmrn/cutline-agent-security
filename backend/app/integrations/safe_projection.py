from __future__ import annotations

from enum import StrEnum
from importlib import import_module
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field

from app.models import (
    ActionType,
    DataClass,
    Event,
    PolicyDecision,
    RunMode,
    RunResult,
    TrustLevel,
)

EventId = Annotated[str, Field(pattern=r"^evt_[0-9a-f]{8}$")]


class SafeToolCategory(StrEnum):
    TASK = "task"
    INSTRUCTION_READ = "instruction_read"
    FILE_READ = "file_read"
    EXTERNAL_WRITE = "external_write"
    FILE_WRITE = "file_write"
    TEST_RUN = "test_run"
    UNKNOWN = "unknown"


class SafeOutcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    BLOCKED = "blocked"
    UNKNOWN = "unknown"


class SafeProvider(StrEnum):
    LOCAL = "local"
    MODAL = "modal"
    UNKNOWN = "unknown"


class SafeRunStatus(StrEnum):
    INCIDENT_DETECTED = "incident_detected"
    PATCH_VERIFIED = "patch_verified"
    RUN_COMPLETE = "run_complete"
    UNKNOWN = "unknown"


class SafeEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: EventId
    parent_event_id: EventId | None = None
    sequence_number: int = Field(ge=1)
    source_trust: TrustLevel
    data_class: DataClass
    action_type: ActionType
    policy_decision: PolicyDecision
    tool_category: SafeToolCategory
    outcome: SafeOutcome


class SafeRun(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: RunMode
    provider: SafeProvider
    status: SafeRunStatus
    secret_exposed: bool
    exfiltration_attempted: bool
    exfiltration_blocked: bool
    code_fixed: bool
    tests_passed: bool
    collector_count: int = Field(ge=0)
    events: list[SafeEvent]


_TOOL_CATEGORIES = {
    "start_task": SafeToolCategory.TASK,
    "read_workspace_rule": SafeToolCategory.INSTRUCTION_READ,
    "read_file": SafeToolCategory.FILE_READ,
    "upload_artifact": SafeToolCategory.EXTERNAL_WRITE,
    "write_file": SafeToolCategory.FILE_WRITE,
    "run_tests": SafeToolCategory.TEST_RUN,
}

_OUTCOMES = {
    "success": SafeOutcome.SUCCESS,
    "failure": SafeOutcome.FAILURE,
    "blocked": SafeOutcome.BLOCKED,
}

_PROVIDERS = {
    "local": SafeProvider.LOCAL,
    "modal": SafeProvider.MODAL,
}

_RUN_STATUSES = {
    "INCIDENT DETECTED": SafeRunStatus.INCIDENT_DETECTED,
    "PATCH VERIFIED": SafeRunStatus.PATCH_VERIFIED,
    "RUN COMPLETE": SafeRunStatus.RUN_COMPLETE,
}

_TELEMETRY_ADAPTER_MODULES = (
    "app.integrations.langfuse_trace",
    "app.integrations.overmind_trace",
)


def project_event(event: Event) -> SafeEvent:
    return SafeEvent(
        event_id=event.event_id,
        parent_event_id=event.parent_event_id,
        sequence_number=event.sequence_number,
        source_trust=event.source_trust,
        data_class=event.data_class,
        action_type=event.action_type,
        policy_decision=event.policy_decision,
        tool_category=_TOOL_CATEGORIES.get(
            event.tool_name, SafeToolCategory.UNKNOWN
        ),
        outcome=_OUTCOMES.get(event.outcome, SafeOutcome.UNKNOWN),
    )


def project_run(run: RunResult) -> SafeRun:
    return SafeRun(
        mode=run.mode,
        provider=_PROVIDERS.get(run.provider, SafeProvider.UNKNOWN),
        status=_RUN_STATUSES.get(run.status, SafeRunStatus.UNKNOWN),
        secret_exposed=run.secret_exposed,
        exfiltration_attempted=run.exfiltration_attempted,
        exfiltration_blocked=run.exfiltration_blocked,
        code_fixed=run.code_fixed,
        tests_passed=run.tests_passed,
        collector_count=run.collector_count,
        events=[project_event(event) for event in run.events],
    )


def emit_run_telemetry(run: RunResult) -> None:
    try:
        safe_run = project_run(run)
    except Exception:  # noqa: BLE001 - telemetry cannot fail a local result
        return

    for module_name in _TELEMETRY_ADAPTER_MODULES:
        try:
            adapter = import_module(module_name)
            adapter.trace_run(safe_run)
        except Exception:  # noqa: BLE001, S112 - isolate optional adapters
            continue
