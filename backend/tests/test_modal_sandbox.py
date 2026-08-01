from __future__ import annotations

from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

import pytest

import modal_sandbox
from app.models import (
    DestinationMatch,
    EvidenceGraph,
    ExecutionProvider,
    PolicyEffect,
    PolicyMatch,
    ProposedPolicy,
    RunMode,
    RunResult,
)
from app.providers import ModalReplayProvider, ProviderUnavailable

EXPECTED_MODAL_ERROR = "Modal replay could not be securely verified."
WORKER_SENTINEL = "CUTLINE_RESULT="


@pytest.fixture
def policy() -> ProposedPolicy:
    return ProposedPolicy(
        id="block-secret-egress",
        version=1,
        policy_hash="a" * 64,
        title="Block unauthorized secret egress",
        description="Synthetic policy fixture.",
        effect=PolicyEffect.DENY,
        match=PolicyMatch(
            data_class="SECRET",
            action_type="EXTERNAL_WRITE",
            destination=DestinationMatch.NOT_IN_SESSION_ALLOWLIST,
        ),
        disruption_score=1,
        evidence_event_ids=["evt-1", "evt-2", "evt-3"],
        candidates=[],
        yaml="effect: DENY\n",
    )


def verified_result(**changes: Any) -> RunResult:
    values: dict[str, Any] = {
        "session_id": "session_modal",
        "fixture_id": "fixture_modal",
        "mode": RunMode.ENFORCE,
        "provider": ExecutionProvider.MODAL.value,
        "status": "PATCH VERIFIED",
        "secret_exposed": False,
        "exfiltration_attempted": True,
        "exfiltration_blocked": True,
        "code_fixed": True,
        "tests_passed": True,
        "test_output": "1 passed",
        "collector_count": 0,
        "events": [],
        "graph": EvidenceGraph(nodes=[], edges=[]),
    }
    values.update(changes)
    return RunResult(**values)


class Reader:
    def __init__(self, value: str) -> None:
        self.value = value

    def read(self) -> str:
        return self.value


@dataclass
class FakeProcess:
    stdout_text: str
    stderr_text: str = ""
    returncode: int = 0
    waited: bool = False

    def __post_init__(self) -> None:
        self.stdout = Reader(self.stdout_text)
        self.stderr = Reader(self.stderr_text)

    def wait(self) -> None:
        self.waited = True


@dataclass
class FakeSandbox:
    process: FakeProcess | None = None
    exec_error: Exception | None = None
    terminate_error: Exception | None = None
    detach_error: Exception | None = None
    cleanup_events: list[str] = field(default_factory=list)
    exec_calls: list[tuple[tuple[str, ...], dict[str, Any]]] = field(
        default_factory=list
    )

    def exec(self, *args: str, **kwargs: Any) -> FakeProcess:
        self.exec_calls.append((args, kwargs))
        if self.exec_error is not None:
            raise self.exec_error
        assert self.process is not None
        return self.process

    def terminate(self, *, wait: bool = False) -> None:
        self.cleanup_events.append(f"terminate:{wait}")
        if self.terminate_error is not None:
            raise self.terminate_error

    def detach(self) -> None:
        self.cleanup_events.append("detach")
        if self.detach_error is not None:
            raise self.detach_error


class FakeImage:
    def __init__(self, calls: list[tuple[str, Any]]) -> None:
        self.calls = calls

    def uv_pip_install(self, *packages: str, **kwargs: Any) -> FakeImage:
        self.calls.append(("uv_pip_install", (packages, kwargs)))
        return self

    def add_local_python_source(self, *modules: str) -> FakeImage:
        self.calls.append(("add_local_python_source", modules))
        return self


@dataclass
class ModalBoundary:
    sandbox: FakeSandbox
    lookup_calls: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    image_calls: list[tuple[str, Any]] = field(default_factory=list)
    create_calls: list[dict[str, Any]] = field(default_factory=list)

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        boundary = self

        class App:
            @staticmethod
            def lookup(name: str, **kwargs: Any) -> object:
                boundary.lookup_calls.append((name, kwargs))
                return object()

        class Image:
            @staticmethod
            def debian_slim(**kwargs: Any) -> FakeImage:
                boundary.image_calls.append(("debian_slim", kwargs))
                return FakeImage(boundary.image_calls)

        class Sandbox:
            @staticmethod
            def create(**kwargs: Any) -> FakeSandbox:
                boundary.create_calls.append(kwargs)
                return boundary.sandbox

        monkeypatch.setattr(
            modal_sandbox,
            "modal",
            SimpleNamespace(App=App, Image=Image, Sandbox=Sandbox),
        )


def result_stdout(result: RunResult) -> str:
    return f"worker log\n{WORKER_SENTINEL}{result.model_dump_json()}\n"


def test_verified_replay_uses_locked_down_modal_contract(
    monkeypatch: pytest.MonkeyPatch,
    policy: ProposedPolicy,
) -> None:
    process = FakeProcess(result_stdout(verified_result()))
    sandbox = FakeSandbox(process=process)
    boundary = ModalBoundary(sandbox)
    boundary.install(monkeypatch)

    result = modal_sandbox.run_in_modal(RunMode.ENFORCE, policy=policy)

    assert result.provider == ExecutionProvider.MODAL.value
    assert boundary.lookup_calls == [("cutline-replay", {"create_if_missing": True})]
    assert boundary.image_calls == [
        ("debian_slim", {"python_version": "3.12"}),
        (
            "uv_pip_install",
            (
                ("pydantic==2.13.4", "PyYAML==6.0.3", "pytest==9.1.1"),
                {"secrets": ()},
            ),
        ),
        ("add_local_python_source", ("app",)),
    ]
    assert len(boundary.create_calls) == 1
    create_kwargs = boundary.create_calls[0]
    assert create_kwargs == {
        "app": create_kwargs["app"],
        "image": create_kwargs["image"],
        "block_network": True,
        "timeout": 120,
        "secrets": (),
        "volumes": {},
        "encrypted_ports": (),
        "h2_ports": (),
        "unencrypted_ports": (),
        "custom_domain": None,
        "proxy": None,
        "include_oidc_identity_token": False,
    }
    assert sandbox.exec_calls == [
        (
            (
                "python",
                "-m",
                "app.modal_worker",
                "--mode",
                "enforce",
                "--policy-json",
                policy.model_dump_json(),
            ),
            {"timeout": 90, "secrets": ()},
        )
    ]
    assert process.waited is True
    assert sandbox.cleanup_events == ["terminate:True", "detach"]


@pytest.mark.parametrize(
    ("mode", "has_policy"),
    [
        (RunMode.MONITOR, True),
        (RunMode.ENFORCE, False),
    ],
)
def test_invalid_request_is_rejected_before_modal_lookup(
    monkeypatch: pytest.MonkeyPatch,
    policy: ProposedPolicy,
    mode: RunMode,
    has_policy: bool,
) -> None:
    boundary = ModalBoundary(FakeSandbox())
    boundary.install(monkeypatch)

    with pytest.raises(modal_sandbox.ModalReplayError) as exc_info:
        modal_sandbox.run_in_modal(mode, policy=policy if has_policy else None)

    assert str(exc_info.value) == EXPECTED_MODAL_ERROR
    assert boundary.lookup_calls == []


@pytest.mark.parametrize(
    ("stdout", "stderr", "returncode"),
    [
        ("worker log only", "", 0),
        (
            f"{WORKER_SENTINEL}{{}}\n{WORKER_SENTINEL}{{}}",
            "",
            0,
        ),
        (f"{WORKER_SENTINEL}not-json", "", 0),
        ("", "CUTLINE_CANARY_7F3A raw worker failure", 7),
    ],
)
def test_unverified_worker_output_raises_one_fixed_redacted_error(
    monkeypatch: pytest.MonkeyPatch,
    policy: ProposedPolicy,
    stdout: str,
    stderr: str,
    returncode: int,
) -> None:
    sandbox = FakeSandbox(
        process=FakeProcess(stdout, stderr_text=stderr, returncode=returncode)
    )
    ModalBoundary(sandbox).install(monkeypatch)

    with pytest.raises(modal_sandbox.ModalReplayError) as exc_info:
        modal_sandbox.run_in_modal(RunMode.ENFORCE, policy=policy)

    message = str(exc_info.value)
    assert message == EXPECTED_MODAL_ERROR
    assert len(message) <= 96
    assert "CUTLINE_CANARY_7F3A" not in message
    assert "worker" not in message.lower()
    assert sandbox.cleanup_events == ["terminate:True", "detach"]


@pytest.mark.parametrize(
    ("field", "unsafe_value"),
    [
        ("mode", RunMode.MONITOR),
        ("provider", ExecutionProvider.LOCAL.value),
        ("secret_exposed", True),
        ("exfiltration_attempted", False),
        ("exfiltration_blocked", False),
        ("collector_count", 1),
        ("code_fixed", False),
        ("tests_passed", False),
    ],
)
def test_result_must_satisfy_every_security_and_utility_invariant(
    monkeypatch: pytest.MonkeyPatch,
    policy: ProposedPolicy,
    field: str,
    unsafe_value: Any,
) -> None:
    sandbox = FakeSandbox(
        process=FakeProcess(result_stdout(verified_result(**{field: unsafe_value})))
    )
    ModalBoundary(sandbox).install(monkeypatch)

    with pytest.raises(modal_sandbox.ModalReplayError) as exc_info:
        modal_sandbox.run_in_modal(RunMode.ENFORCE, policy=policy)

    assert str(exc_info.value) == EXPECTED_MODAL_ERROR
    assert sandbox.cleanup_events == ["terminate:True", "detach"]


def test_modal_boundary_exception_still_terminates_then_detaches(
    monkeypatch: pytest.MonkeyPatch,
    policy: ProposedPolicy,
) -> None:
    sandbox = FakeSandbox(exec_error=RuntimeError("CUTLINE_CANARY_7F3A"))
    ModalBoundary(sandbox).install(monkeypatch)

    with pytest.raises(modal_sandbox.ModalReplayError) as exc_info:
        modal_sandbox.run_in_modal(RunMode.ENFORCE, policy=policy)

    assert str(exc_info.value) == EXPECTED_MODAL_ERROR
    assert sandbox.cleanup_events == ["terminate:True", "detach"]


@pytest.mark.parametrize("cleanup_failure", ["terminate", "detach"])
def test_cleanup_failure_is_redacted_and_detach_is_always_attempted(
    monkeypatch: pytest.MonkeyPatch,
    policy: ProposedPolicy,
    cleanup_failure: str,
) -> None:
    sandbox = FakeSandbox(process=FakeProcess(result_stdout(verified_result())))
    setattr(
        sandbox,
        f"{cleanup_failure}_error",
        RuntimeError("CUTLINE_CANARY_7F3A cleanup traceback"),
    )
    ModalBoundary(sandbox).install(monkeypatch)

    with pytest.raises(modal_sandbox.ModalReplayError) as exc_info:
        modal_sandbox.run_in_modal(RunMode.ENFORCE, policy=policy)

    assert str(exc_info.value) == EXPECTED_MODAL_ERROR
    assert sandbox.cleanup_events == ["terminate:True", "detach"]


def test_provider_does_not_expose_modal_failure_details(
    monkeypatch: pytest.MonkeyPatch,
    policy: ProposedPolicy,
) -> None:
    monkeypatch.setenv("CUTLINE_MODAL_ENABLED", "1")

    def fail_run(*args: Any, **kwargs: Any) -> RunResult:
        raise RuntimeError("CUTLINE_CANARY_7F3A remote traceback")

    monkeypatch.setattr(modal_sandbox, "run_in_modal", fail_run)

    with pytest.raises(ProviderUnavailable) as exc_info:
        ModalReplayProvider().replay(policy)

    assert str(exc_info.value) == EXPECTED_MODAL_ERROR
    assert len(str(exc_info.value)) <= 96
