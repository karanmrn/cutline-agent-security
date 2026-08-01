import pytest

from app.event_bus import EventRecorder
from app.integrations.overmind_trace import sanitized_event_attributes, status
from app.integrations.supabase_store import SupabaseMirror, mirror_rows
from app.models import ActionType, DataClass, Event, PolicyDecision, RunMode, TrustLevel
from app.policy import build_policy
from app.regression import build_regression_manifest, verify_regression_manifest
from app.runner import SYNTHETIC_CANARY, AgentRunner


def test_overmind_event_attributes_never_include_secret_bearing_arguments() -> None:
    event = Event(
        event_id="evt_secret",
        session_id="session_safe",
        sequence_number=3,
        actor="coding-agent",
        source_type="tool_call",
        source_trust=TrustLevel.UNTRUSTED,
        data_class=DataClass.SECRET,
        tool_name="upload_artifact",
        destination="external-support",
        action_type=ActionType.EXTERNAL_WRITE,
        arguments_redacted={"payload": SYNTHETIC_CANARY},
        policy_decision=PolicyDecision.DENY,
        outcome="blocked",
        message=f"must not export {SYNTHETIC_CANARY}",
    )

    attributes = sanitized_event_attributes(event)

    assert attributes == {
        "cutline.event_id": "evt_secret",
        "cutline.session_id": "session_safe",
        "cutline.sequence_number": 3,
        "cutline.source_trust": "UNTRUSTED",
        "cutline.data_class": "SECRET",
        "cutline.tool_name": "upload_artifact",
        "cutline.action_type": "EXTERNAL_WRITE",
        "cutline.policy_decision": "DENY",
        "cutline.outcome": "blocked",
    }
    assert SYNTHETIC_CANARY not in str(attributes)


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
    manifest = build_regression_manifest(
        vulnerable_run=vulnerable,
        replay_run=replay,
        policy=policy,
    )

    rows = mirror_rows(vulnerable, replay, policy, manifest)
    serialized = str(rows)

    assert SYNTHETIC_CANARY not in serialized
    assert rows["incidents"][0]["evidence_event_ids"] == policy.evidence_event_ids
    assert rows["policies"][0]["policy_hash"] == policy.policy_hash
    assert rows["replays"][0]["digest_sha256"] == manifest.digest_sha256
    assert all("parent_event_id" in row for row in rows["events"])


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
    manifest = build_regression_manifest(
        vulnerable_run=vulnerable,
        replay_run=replay,
        policy=policy,
    )
    client = Client()

    SupabaseMirror(client=client).persist(vulnerable, replay, policy, manifest)

    assert {name for name, _row in client.calls} == {
        "cutline_sessions",
        "cutline_events",
        "cutline_incidents",
        "cutline_policies",
        "cutline_replays",
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
