from __future__ import annotations

import importlib
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from app.integrations import overmind_trace as module
from app.integrations.safe_projection import (
    SafeEvent,
    SafeOutcome,
    SafeProvider,
    SafeRun,
    SafeRunStatus,
    SafeToolCategory,
)
from app.models import ActionType, DataClass, PolicyDecision, RunMode, TrustLevel


@pytest.fixture
def adapter(monkeypatch):
    loaded = importlib.reload(module)
    monkeypatch.delenv("CUTLINE_OVERMIND_ENABLED", raising=False)
    monkeypatch.delenv("OVERMIND_API_KEY", raising=False)
    monkeypatch.delenv("OVERMIND_AGENT_ID", raising=False)
    monkeypatch.delenv("OVERMIND_PROJECT_ID", raising=False)
    return loaded


@pytest.fixture
def safe_run() -> SafeRun:
    categories = (
        SafeToolCategory.TASK,
        SafeToolCategory.INSTRUCTION_READ,
        SafeToolCategory.FILE_READ,
        SafeToolCategory.EXTERNAL_WRITE,
        SafeToolCategory.FILE_WRITE,
        SafeToolCategory.TEST_RUN,
    )
    events = [
        SafeEvent(
            event_id=f"evt_{index:08x}",
            parent_event_id=None if index == 1 else f"evt_{index - 1:08x}",
            sequence_number=index,
            source_trust=TrustLevel.UNTRUSTED,
            data_class=DataClass.SECRET if index in {3, 4} else DataClass.INTERNAL,
            action_type=(
                ActionType.EXTERNAL_WRITE if index == 4 else ActionType.EXECUTE
            ),
            policy_decision=(
                PolicyDecision.DENY if index == 4 else PolicyDecision.ALLOW
            ),
            tool_category=category,
            outcome=SafeOutcome.BLOCKED if index == 4 else SafeOutcome.SUCCESS,
        )
        for index, category in enumerate(categories, start=1)
    ]
    return SafeRun(
        mode=RunMode.ENFORCE,
        provider=SafeProvider.LOCAL,
        status=SafeRunStatus.PATCH_VERIFIED,
        secret_exposed=False,
        exfiltration_attempted=True,
        exfiltration_blocked=True,
        code_fixed=True,
        tests_passed=True,
        collector_count=0,
        events=events,
    )


def test_disabled_or_missing_key_never_imports_sdk(adapter, monkeypatch, safe_run) -> None:
    monkeypatch.setattr(
        adapter,
        "import_module",
        lambda name: pytest.fail(f"unexpected import: {name}"),
    )
    adapter.trace_run(safe_run)
    assert adapter.status()["state"] == "disabled"

    monkeypatch.setenv("CUTLINE_OVERMIND_ENABLED", "1")
    adapter.trace_run(safe_run)
    assert adapter.status() == {
        "provider": "overmind",
        "state": "error",
        "configured": False,
        "last_checked_at": None,
        "message": "Overmind configuration is incomplete.",
    }


def test_trace_is_one_fixed_tree_with_no_input_or_output_capture(
    adapter, monkeypatch, safe_run
) -> None:
    monkeypatch.setenv("CUTLINE_OVERMIND_ENABLED", "1")
    monkeypatch.setenv("OVERMIND_API_KEY", "synthetic-overmind-key")
    monkeypatch.setenv("OVERMIND_AGENT_ID", "agent-synthetic")
    monkeypatch.setenv("OVERMIND_PROJECT_ID", "project-synthetic")
    init_calls: list[dict] = []
    spans: list[tuple[str, str, dict, str | None]] = []
    active: list[str] = []
    flushes: list[int] = []

    @contextmanager
    def start_span(name, *, span_type, attributes):
        spans.append((name, span_type, attributes, active[-1] if active else None))
        active.append(name)
        try:
            yield object()
        finally:
            active.pop()

    fake = SimpleNamespace(
        SpanType=SimpleNamespace(
            ENTRY_POINT="entry_point",
            WORKFLOW="workflow",
            TOOL="tool_call",
            RETRIEVAL="retrieval",
        ),
        init=lambda **kwargs: init_calls.append(kwargs),
        start_span=start_span,
        force_flush_traces=lambda timeout_millis: flushes.append(timeout_millis),
    )
    monkeypatch.setattr(adapter, "import_module", lambda name: fake)

    adapter.trace_run(safe_run)

    assert init_calls == [
        {
            "overmind_api_key": "synthetic-overmind-key",
            "service_name": "cutline-agent-security",
            "environment": "demo",
            "providers": None,
            "agent_id": "agent-synthetic",
            "agent_name": "CUTLINE Replay Agent",
            "project_id": "project-synthetic",
        }
    ]
    assert [(name, kind, parent) for name, kind, _attrs, parent in spans] == [
        ("cutline.run", "entry_point", None),
        ("cutline.fix-and-verify", "workflow", "cutline.run"),
        ("cutline.event.task", "tool_call", "cutline.fix-and-verify"),
        ("cutline.event.instruction-read", "retrieval", "cutline.fix-and-verify"),
        ("cutline.event.file-read", "retrieval", "cutline.fix-and-verify"),
        ("cutline.event.external-write", "tool_call", "cutline.fix-and-verify"),
        ("cutline.event.file-write", "tool_call", "cutline.fix-and-verify"),
        ("cutline.event.test-run", "tool_call", "cutline.fix-and-verify"),
    ]
    serialized = str(spans)
    for forbidden in (
        "CUTLINE_CANARY_7F3A",
        "synthetic-overmind-key",
        "inputs",
        "outputs",
        "session_",
        "fixture_",
        ".env",
    ):
        assert forbidden not in serialized
    assert flushes == [1000]
    assert adapter.status()["state"] == "unverified"
    assert "ingestion remains unverified" in adapter.status()["message"]


@pytest.mark.parametrize("stage", ["init", "span", "flush"])
def test_sdk_failures_never_escape(adapter, monkeypatch, safe_run, stage) -> None:
    monkeypatch.setenv("CUTLINE_OVERMIND_ENABLED", "1")
    monkeypatch.setenv("OVERMIND_API_KEY", "synthetic-overmind-key")

    @contextmanager
    def start_span(*_args, **_kwargs):
        if stage == "span":
            raise RuntimeError("CUTLINE_CANARY_7F3A")
        yield object()

    def initialize(**_kwargs):
        if stage == "init":
            raise RuntimeError("CUTLINE_CANARY_7F3A")

    def flush(_timeout):
        if stage == "flush":
            raise RuntimeError("CUTLINE_CANARY_7F3A")

    fake = SimpleNamespace(
        SpanType=SimpleNamespace(
            ENTRY_POINT="entry_point",
            WORKFLOW="workflow",
            TOOL="tool_call",
            RETRIEVAL="retrieval",
        ),
        init=initialize,
        start_span=start_span,
        force_flush_traces=flush,
    )
    monkeypatch.setattr(adapter, "import_module", lambda name: fake)

    adapter.trace_run(safe_run)

    status = adapter.status()
    assert status["state"] == "error"
    assert "CUTLINE_CANARY" not in str(status)
