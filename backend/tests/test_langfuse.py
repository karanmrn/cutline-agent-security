from __future__ import annotations

import importlib
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

import pytest

from app.integrations import langfuse_trace as langfuse_trace_module
from app.integrations.safe_projection import (
    SafeEvent,
    SafeOutcome,
    SafeProvider,
    SafeRun,
    SafeRunStatus,
    SafeToolCategory,
)
from app.models import ActionType, DataClass, PolicyDecision, RunMode, TrustLevel
from app.state import DemoStore


@pytest.fixture
def adapter(monkeypatch):
    module = importlib.reload(langfuse_trace_module)
    monkeypatch.delenv("CUTLINE_LANGFUSE_ENABLED", raising=False)
    monkeypatch.delenv("LANGFUSE_PUBLIC_KEY", raising=False)
    monkeypatch.delenv("LANGFUSE_SECRET_KEY", raising=False)
    monkeypatch.delenv("LANGFUSE_BASE_URL", raising=False)
    return module


@pytest.fixture
def safe_run() -> SafeRun:
    categories = (
        (SafeToolCategory.TASK, ActionType.EXECUTE, DataClass.INTERNAL),
        (SafeToolCategory.INSTRUCTION_READ, ActionType.READ, DataClass.INTERNAL),
        (SafeToolCategory.FILE_READ, ActionType.READ, DataClass.SECRET),
        (
            SafeToolCategory.EXTERNAL_WRITE,
            ActionType.EXTERNAL_WRITE,
            DataClass.SECRET,
        ),
        (SafeToolCategory.FILE_WRITE, ActionType.WRITE, DataClass.INTERNAL),
        (SafeToolCategory.TEST_RUN, ActionType.EXECUTE, DataClass.INTERNAL),
    )
    events = [
        SafeEvent(
            event_id=f"evt_{index:08x}",
            parent_event_id=None if index == 1 else f"evt_{index - 1:08x}",
            sequence_number=index,
            source_trust=(
                TrustLevel.UNTRUSTED if index in {2, 3, 4} else TrustLevel.TRUSTED
            ),
            data_class=data_class,
            action_type=action_type,
            policy_decision=(
                PolicyDecision.DENY if index == 4 else PolicyDecision.ALLOW
            ),
            tool_category=category,
            outcome=SafeOutcome.BLOCKED if index == 4 else SafeOutcome.SUCCESS,
        )
        for index, (category, action_type, data_class) in enumerate(
            categories, start=1
        )
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


def enable(monkeypatch) -> None:
    monkeypatch.setenv("CUTLINE_LANGFUSE_ENABLED", "1")
    monkeypatch.setenv("LANGFUSE_PUBLIC_KEY", "synthetic-public-key")
    monkeypatch.setenv("LANGFUSE_SECRET_KEY", "synthetic-secret-key")
    monkeypatch.setenv("LANGFUSE_BASE_URL", "https://langfuse.invalid")


@dataclass
class ObservationCall:
    kwargs: dict[str, Any]
    parent_name: str | None
    closed: bool = False


class ObservationContext:
    def __init__(self, client: FakeClient, call: ObservationCall) -> None:
        self.client = client
        self.call = call

    def __enter__(self) -> object:
        if self.client.enter_failure_at == len(self.client.calls):
            raise RuntimeError("CUTLINE_CANARY_7F3A enter failure")
        self.client.active.append(self.call)
        return object()

    def __exit__(self, *_args: object) -> None:
        self.client.active.pop()
        if self.client.close_failure_at == len(self.client.closed) + 1:
            raise RuntimeError("CUTLINE_CANARY_7F3A close failure")
        self.call.closed = True
        self.client.closed.append(self.call.kwargs["name"])


class FakeClient:
    def __init__(
        self,
        *,
        observation_failure_at: int | None = None,
        enter_failure_at: int | None = None,
        close_failure_at: int | None = None,
        flush_fails: bool = False,
    ) -> None:
        self.calls: list[ObservationCall] = []
        self.active: list[ObservationCall] = []
        self.closed: list[str] = []
        self.observation_failure_at = observation_failure_at
        self.enter_failure_at = enter_failure_at
        self.close_failure_at = close_failure_at
        self.flush_fails = flush_fails
        self.flush_count = 0
        self.flush_saw_open_observations: bool | None = None

    def start_as_current_observation(self, **kwargs: Any) -> ObservationContext:
        next_call = len(self.calls) + 1
        if self.observation_failure_at == next_call:
            raise RuntimeError("CUTLINE_CANARY_7F3A observation failure")
        call = ObservationCall(
            kwargs=kwargs,
            parent_name=self.active[-1].kwargs["name"] if self.active else None,
        )
        self.calls.append(call)
        return ObservationContext(self, call)

    def flush(self) -> None:
        self.flush_count += 1
        self.flush_saw_open_observations = bool(self.active)
        if self.flush_fails:
            raise RuntimeError("CUTLINE_CANARY_7F3A flush failure")


def install_fake_sdk(monkeypatch, adapter, client: FakeClient) -> list[dict[str, Any]]:
    requested_configurations: list[dict[str, Any]] = []

    def create_client(**configuration: Any) -> FakeClient:
        requested_configurations.append(configuration)
        return client

    monkeypatch.setattr(
        adapter,
        "import_module",
        lambda name: SimpleNamespace(Langfuse=create_client)
        if name == "langfuse"
        else pytest.fail(f"unexpected import: {name}"),
    )
    return requested_configurations


def test_disabled_adapter_never_imports_sdk(adapter, monkeypatch, safe_run) -> None:
    monkeypatch.setattr(
        adapter,
        "import_module",
        lambda name: pytest.fail(f"disabled adapter imported {name}"),
    )

    adapter.trace_run(safe_run)

    assert adapter.status() == {
        "provider": "langfuse",
        "state": "disabled",
        "configured": False,
        "last_checked_at": None,
        "message": "Set CUTLINE_LANGFUSE_ENABLED=1 after configuring Langfuse.",
    }


def test_demo_state_exposes_canonical_langfuse_status(adapter) -> None:
    integration = DemoStore().snapshot().integrations["langfuse"]

    assert integration.model_dump(mode="json") == adapter.status()


@pytest.mark.parametrize(
    "missing_name",
    ["LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY", "LANGFUSE_BASE_URL"],
)
def test_enabled_adapter_requires_complete_configuration_before_sdk_import(
    adapter, monkeypatch, safe_run, missing_name
) -> None:
    enable(monkeypatch)
    monkeypatch.delenv(missing_name)
    monkeypatch.setattr(
        adapter,
        "import_module",
        lambda name: pytest.fail(f"incomplete config imported {name}"),
    )

    adapter.trace_run(safe_run)

    assert adapter.status() == {
        "provider": "langfuse",
        "state": "error",
        "configured": False,
        "last_checked_at": None,
        "message": "Langfuse configuration is incomplete.",
    }


def test_trace_uses_fixed_nested_observations_without_capture(
    adapter, monkeypatch, safe_run
) -> None:
    enable(monkeypatch)
    client = FakeClient()
    requested_configurations = install_fake_sdk(monkeypatch, adapter, client)

    adapter.trace_run(safe_run)

    assert requested_configurations == [
        {
            "public_key": "synthetic-public-key",
            "secret_key": "synthetic-secret-key",
            "base_url": "https://langfuse.invalid",
            "tracing_enabled": True,
        }
    ]
    assert [(call.kwargs, call.parent_name) for call in client.calls] == [
        ({"name": "cutline-run", "as_type": "agent"}, None),
        ({"name": "fix-and-verify", "as_type": "chain"}, "cutline-run"),
        ({"name": "task", "as_type": "span"}, "fix-and-verify"),
        (
            {"name": "instruction-read", "as_type": "retriever"},
            "fix-and-verify",
        ),
        ({"name": "file-read", "as_type": "retriever"}, "fix-and-verify"),
        ({"name": "external-write", "as_type": "tool"}, "fix-and-verify"),
        ({"name": "file-write", "as_type": "tool"}, "fix-and-verify"),
        ({"name": "test-run", "as_type": "tool"}, "fix-and-verify"),
    ]
    assert client.closed == [
        "task",
        "instruction-read",
        "file-read",
        "external-write",
        "file-write",
        "test-run",
        "fix-and-verify",
        "cutline-run",
    ]
    assert client.flush_count == 1
    assert client.flush_saw_open_observations is False
    assert adapter.status() == {
        "provider": "langfuse",
        "state": "unverified",
        "configured": True,
        "last_checked_at": None,
        "message": "Telemetry flush completed; provider ingestion remains unverified.",
    }


def test_client_creation_is_unverified_until_a_trace_flushes(
    adapter, monkeypatch
) -> None:
    enable(monkeypatch)
    client = FakeClient()
    install_fake_sdk(monkeypatch, adapter, client)

    assert adapter._get_client() is client
    assert adapter.status() == {
        "provider": "langfuse",
        "state": "unverified",
        "configured": True,
        "last_checked_at": None,
        "message": "Langfuse client initialized; no telemetry flush completed.",
    }


@pytest.mark.parametrize(
    ("failure", "expected_message"),
    [
        ("initialization", "Langfuse client initialization failed."),
        ("observation", "Langfuse observation failed."),
        ("close", "Langfuse observation failed."),
        ("flush", "Langfuse telemetry flush failed."),
    ],
)
def test_sdk_failures_never_escape_or_expose_exception_text(
    adapter, monkeypatch, safe_run, failure, expected_message
) -> None:
    enable(monkeypatch)
    if failure == "initialization":
        monkeypatch.setattr(
            adapter,
            "import_module",
            lambda _name: SimpleNamespace(
                Langfuse=lambda **_kwargs: (_ for _ in ()).throw(
                    RuntimeError("CUTLINE_CANARY_7F3A init failure")
                )
            ),
        )
    else:
        client = FakeClient(
            observation_failure_at=3 if failure == "observation" else None,
            close_failure_at=1 if failure == "close" else None,
            flush_fails=failure == "flush",
        )
        install_fake_sdk(monkeypatch, adapter, client)

    adapter.trace_run(safe_run)

    result = adapter.status()
    assert result["state"] == "error"
    assert result["configured"] is True
    assert result["message"] == expected_message
    assert "CUTLINE_CANARY_7F3A" not in str(result)
