import pytest
from pydantic import ValidationError

from app.event_bus import EventRecorder
from app.integrations import safe_projection
from app.integrations.overmind_trace import status
from app.integrations.safe_projection import (
    SafeEvent,
    SafeOutcome,
    SafeProvider,
    SafeRunStatus,
    SafeToolCategory,
    emit_run_telemetry,
    project_event,
    project_run,
)
from app.integrations.supabase_store import SupabaseMirror, mirror_rows
from app.models import ActionType, DataClass, Event, PolicyDecision, RunMode, TrustLevel
from app.policy import build_policy
from app.regression import build_regression_manifest, verify_regression_manifest
from app.runner import SYNTHETIC_CANARY, AgentRunner
from app.state import DemoStore


def test_safe_event_projection_excludes_every_free_text_field() -> None:
    credential = "sk-synthetic-not-a-real-credential"
    event = Event(
        event_id="evt_a1b2c3d4",
        session_id=f"session-{SYNTHETIC_CANARY}-{credential}",
        parent_event_id="evt_0123abcd",
        sequence_number=7,
        actor=f"actor-{SYNTHETIC_CANARY}-{credential}",
        source_type=f"source-{SYNTHETIC_CANARY}-{credential}",
        source_trust=TrustLevel.UNTRUSTED,
        data_class=DataClass.SECRET,
        tool_name=f"tool-{SYNTHETIC_CANARY}-{credential}",
        resource=f"resource-{SYNTHETIC_CANARY}-{credential}",
        destination=f"destination-{SYNTHETIC_CANARY}-{credential}",
        action_type=ActionType.EXTERNAL_WRITE,
        arguments_redacted={"payload": f"{SYNTHETIC_CANARY}-{credential}"},
        policy_decision=PolicyDecision.DENY,
        outcome=f"outcome-{SYNTHETIC_CANARY}-{credential}",
        message=f"message-{SYNTHETIC_CANARY}-{credential}",
    )

    projected = project_event(event)
    serialized = projected.model_dump(mode="json")

    assert serialized == {
        "event_id": "evt_a1b2c3d4",
        "parent_event_id": "evt_0123abcd",
        "sequence_number": 7,
        "source_trust": "UNTRUSTED",
        "data_class": "SECRET",
        "action_type": "EXTERNAL_WRITE",
        "policy_decision": "DENY",
        "tool_category": "unknown",
        "outcome": "unknown",
    }
    assert SYNTHETIC_CANARY not in projected.model_dump_json()
    assert credential not in projected.model_dump_json()


@pytest.mark.parametrize(
    ("tool_name", "expected"),
    [
        ("start_task", SafeToolCategory.TASK),
        ("read_workspace_rule", SafeToolCategory.INSTRUCTION_READ),
        ("read_file", SafeToolCategory.FILE_READ),
        ("upload_artifact", SafeToolCategory.EXTERNAL_WRITE),
        ("write_file", SafeToolCategory.FILE_WRITE),
        ("run_tests", SafeToolCategory.TEST_RUN),
    ],
)
def test_safe_event_projection_maps_known_tools_to_fixed_categories(
    tool_name: str, expected: SafeToolCategory
) -> None:
    event = Event(
        event_id="evt_a1b2c3d4",
        session_id="unsafe-session-id",
        sequence_number=1,
        actor="unsafe-actor",
        source_type="unsafe-source",
        source_trust=TrustLevel.TRUSTED,
        data_class=DataClass.INTERNAL,
        tool_name=tool_name,
        action_type=ActionType.EXECUTE,
        outcome="success",
        message="unsafe-message",
    )

    assert project_event(event).tool_category == expected
    assert project_event(event).outcome == SafeOutcome.SUCCESS


def test_safe_event_rejects_malformed_event_lineage_ids() -> None:
    with pytest.raises(ValidationError):
        SafeEvent(
            event_id="evt_not-hex",
            parent_event_id="evt_also-not-hex",
            sequence_number=1,
            source_trust=TrustLevel.TRUSTED,
            data_class=DataClass.INTERNAL,
            action_type=ActionType.READ,
            policy_decision=PolicyDecision.NOT_EVALUATED,
            tool_category=SafeToolCategory.UNKNOWN,
            outcome=SafeOutcome.UNKNOWN,
        )


def test_safe_run_projection_excludes_raw_run_and_graph_text() -> None:
    credential = "sk-synthetic-not-a-real-credential"
    forbidden = f"{SYNTHETIC_CANARY}-{credential}"
    run = AgentRunner().run(RunMode.MONITOR)
    poisoned_events = [
        run.events[0].model_copy(
            update={
                "event_id": "evt_a1b2c3d4",
                "actor": forbidden,
                "source_type": forbidden,
                "tool_name": forbidden,
                "resource": forbidden,
                "destination": forbidden,
                "arguments_redacted": {"payload": forbidden},
                "outcome": forbidden,
                "message": forbidden,
            }
        )
    ]
    poisoned_graph = run.graph.model_copy(
        update={
            "nodes": [
                node.model_copy(
                    update={"label": forbidden, "kind": forbidden, "status": forbidden}
                )
                for node in run.graph.nodes
            ],
            "edges": [
                edge.model_copy(update={"label": forbidden, "status": forbidden})
                for edge in run.graph.edges
            ],
        }
    )
    poisoned_run = run.model_copy(
        update={
            "session_id": forbidden,
            "fixture_id": forbidden,
            "provider": forbidden,
            "status": forbidden,
            "test_output": forbidden,
            "events": poisoned_events,
            "graph": poisoned_graph,
        }
    )

    serialized = project_run(poisoned_run).model_dump(mode="json")

    assert serialized == {
        "mode": "monitor",
        "provider": SafeProvider.UNKNOWN.value,
        "status": SafeRunStatus.UNKNOWN.value,
        "secret_exposed": True,
        "exfiltration_attempted": True,
        "exfiltration_blocked": False,
        "code_fixed": True,
        "tests_passed": True,
        "collector_count": 1,
        "events": [
            {
                "event_id": "evt_a1b2c3d4",
                "parent_event_id": None,
                "sequence_number": 1,
                "source_trust": "TRUSTED",
                "data_class": "INTERNAL",
                "action_type": "EXECUTE",
                "policy_decision": "ALLOW",
                "tool_category": "unknown",
                "outcome": "unknown",
            }
        ],
    }
    assert SYNTHETIC_CANARY not in str(serialized)
    assert credential not in str(serialized)


def test_run_telemetry_isolates_each_lazy_adapter_failure(monkeypatch) -> None:
    observed = []
    run = AgentRunner().run(RunMode.MONITOR)

    class FailingAdapter:
        @staticmethod
        def trace_run(_run) -> None:
            raise RuntimeError("synthetic adapter failure")

    class RecordingAdapter:
        @staticmethod
        def trace_run(run) -> None:
            observed.append(run)

    adapters = {
        "app.integrations.langfuse_trace": FailingAdapter,
        "app.integrations.overmind_trace": RecordingAdapter,
    }
    monkeypatch.setattr(
        safe_projection,
        "import_module",
        lambda module_name: adapters[module_name],
    )

    emit_run_telemetry(run)

    assert len(observed) == 1
    assert observed[0].mode == RunMode.MONITOR
    assert SYNTHETIC_CANARY not in observed[0].model_dump_json()


def test_overmind_disabled_status_is_explicit(monkeypatch) -> None:
    monkeypatch.delenv("CUTLINE_OVERMIND_ENABLED", raising=False)

    assert status() == {
        "provider": "overmind",
        "state": "disabled",
        "configured": False,
        "last_checked_at": None,
        "message": "Set CUTLINE_OVERMIND_ENABLED=1 after configuring Overmind.",
    }


def test_event_recorder_publishes_the_completed_event_to_telemetry_sink() -> None:
    published: list[Event] = []
    recorder = EventRecorder(session_id="session_trace", on_event=published.append)

    event = recorder.emit(
        actor="user",
        source_type="user_task",
        source_trust=TrustLevel.TRUSTED,
        data_class=DataClass.INTERNAL,
        tool_name="start_task",
        action_type=ActionType.EXECUTE,
        outcome="success",
        message="Task started.",
    )

    assert published == [event]
    assert recorder.events == [event]


def test_supabase_rows_preserve_lineage_without_secret_payloads() -> None:
    vulnerable = AgentRunner().run(RunMode.MONITOR)
    policy = build_policy(vulnerable.events)
    replay = AgentRunner().run(RunMode.ENFORCE, policy=policy)
    rows = mirror_rows(vulnerable, replay, policy)
    serialized = str(rows)

    assert SYNTHETIC_CANARY not in serialized
    assert rows["incidents"][0]["evidence_event_ids"] == policy.evidence_event_ids
    assert rows["policies"][0]["policy_hash"] == policy.policy_hash
    assert rows["replays"][0]["tests_passed"] is True
    assert all("parent_event_id" in row for row in rows["events"])
    assert all(
        {"actor", "resource", "destination", "message", "tool_name"}.isdisjoint(row)
        for row in rows["events"]
    )


def test_supabase_enabled_without_server_credentials_is_not_configured(monkeypatch) -> None:
    monkeypatch.setenv("CUTLINE_SUPABASE_ENABLED", "1")
    monkeypatch.delenv("SUPABASE_URL", raising=False)
    monkeypatch.delenv("SUPABASE_SERVICE_ROLE_KEY", raising=False)

    status = SupabaseMirror().status()

    assert status["state"] == "error"
    assert status["configured"] is False
    assert "server-side key" in status["message"]
    assert set(status) == {
        "provider",
        "state",
        "configured",
        "last_checked_at",
        "message",
    }


def test_ossprey_stays_quarantined_without_an_official_contract(monkeypatch) -> None:
    monkeypatch.setenv("CUTLINE_OSSPREY_ENABLED", "1")
    monkeypatch.setenv("CUTLINE_OSSPREY_EXECUTABLE", "/synthetic/bin/ossprey")

    status = DemoStore().snapshot().integrations["ossprey"]

    assert status.state.value == "unverified"
    assert status.configured is False
    assert status.last_checked_at is None
    assert status.message == (
        "Awaiting an official Ossprey API, CLI, starter, or sponsor-supported contract."
    )


def test_supabase_enabled_mirror_writes_all_tables_best_effort(monkeypatch) -> None:
    class Table:
        def __init__(self, name: str, calls: list[tuple[str, dict]]) -> None:
            self.name = name
            self.calls = calls

        def upsert(self, row: dict) -> "Table":
            self.calls.append((self.name, row))
            return self

        def execute(self) -> None:
            return None

    class Client:
        def __init__(self) -> None:
            self.calls: list[tuple[str, dict]] = []

        def table(self, name: str) -> Table:
            return Table(name, self.calls)

    monkeypatch.setenv("CUTLINE_SUPABASE_ENABLED", "1")
    vulnerable = AgentRunner().run(RunMode.MONITOR)
    policy = build_policy(vulnerable.events)
    replay = AgentRunner().run(RunMode.ENFORCE, policy=policy)
    client = Client()

    SupabaseMirror(client=client).persist(vulnerable, replay, policy)

    assert {name for name, _row in client.calls} == {
        "cutline_safe_sessions",
        "cutline_safe_events",
        "cutline_safe_incidents",
        "cutline_safe_policies",
        "cutline_safe_replays",
    }
    assert all(SYNTHETIC_CANARY not in str(row) for _name, row in client.calls)


def test_regression_manifest_verifier_rejects_tampering() -> None:
    vulnerable = AgentRunner().run(RunMode.MONITOR)
    policy = build_policy(vulnerable.events)
    replay = AgentRunner().run(RunMode.ENFORCE, policy=policy)
    manifest = build_regression_manifest(
        vulnerable_run=vulnerable,
        replay_run=replay,
        policy=policy,
    )

    assert verify_regression_manifest(manifest) is True
    tampered = manifest.model_copy(
        update={
            "assertions": manifest.assertions.model_copy(
                update={"attack_blocked": False}
            )
        }
    )

    assert verify_regression_manifest(tampered) is False


def test_regression_manifest_builder_rejects_failed_invariants() -> None:
    vulnerable = AgentRunner().run(RunMode.MONITOR)
    policy = build_policy(vulnerable.events)
    replay = AgentRunner().run(RunMode.ENFORCE, policy=policy)
    failed_replay = replay.model_copy(update={"tests_passed": False})

    with pytest.raises(ValueError, match="regression manifest invariants"):
        build_regression_manifest(
            vulnerable_run=vulnerable,
            replay_run=failed_replay,
            policy=policy,
        )
