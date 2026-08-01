from __future__ import annotations

import re
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from app.integrations.supabase_store import SupabaseMirror, mirror_rows
from app.models import RunMode
from app.policy import build_policy
from app.regression import build_regression_manifest
from app.runner import SYNTHETIC_CANARY, AgentRunner

TABLE_ORDER = (
    "sessions",
    "events",
    "incidents",
    "policies",
    "replays",
)
ROW_KEYS = {
    "sessions": {
        "session_id",
        "fixture_id",
        "mode",
        "provider",
        "status",
        "secret_exposed",
        "tests_passed",
    },
    "events": {
        "event_id",
        "session_id",
        "sequence_number",
        "parent_event_id",
        "actor",
        "source_type",
        "source_trust",
        "data_class",
        "tool_name",
        "resource",
        "destination",
        "action_type",
        "policy_decision",
        "outcome",
        "message",
    },
    "incidents": {
        "incident_id",
        "source_session_id",
        "severity",
        "summary",
        "evidence_event_ids",
    },
    "policies": {
        "id",
        "version",
        "policy_hash",
        "effect",
        "disruption_score",
        "evidence_event_ids",
        "policy_yaml",
    },
    "replays": {
        "session_id",
        "policy_id",
        "blocked",
        "utility_retained",
        "digest_sha256",
    },
}


@pytest.fixture
def replay_bundle():
    vulnerable = AgentRunner().run(RunMode.MONITOR)
    policy = build_policy(vulnerable.events)
    replay = AgentRunner().run(RunMode.ENFORCE, policy=policy)
    manifest = build_regression_manifest(
        vulnerable_run=vulnerable,
        replay_run=replay,
        policy=policy,
    )
    return vulnerable, replay, policy, manifest


def _all_strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, nested_value in value.items():
            yield from _all_strings(key)
            yield from _all_strings(nested_value)
    elif isinstance(value, (list, tuple)):
        for nested_value in value:
            yield from _all_strings(nested_value)


def _all_keys(value: Any):
    if isinstance(value, dict):
        for key, nested_value in value.items():
            yield key
            yield from _all_keys(nested_value)
    elif isinstance(value, (list, tuple)):
        for nested_value in value:
            yield from _all_keys(nested_value)


def _sql_columns(sql: str, table: str) -> set[str]:
    match = re.search(
        rf"create table if not exists public\.cutline_{table}\s*\((.*?)\n\);",
        sql,
        flags=re.DOTALL | re.IGNORECASE,
    )
    assert match is not None
    return {
        line.strip().split(maxsplit=1)[0]
        for line in match.group(1).splitlines()
        if line.strip()
    }


def test_rows_match_schema_and_recursively_redact_all_strings(replay_bundle) -> None:
    vulnerable, replay, policy, manifest = replay_bundle
    poisoned_event = vulnerable.events[0].model_copy(
        update={
            "event_id": f"event-{SYNTHETIC_CANARY}",
            "session_id": f"session-{SYNTHETIC_CANARY}",
            "actor": f"actor-{SYNTHETIC_CANARY}",
            "source_type": f"source-{SYNTHETIC_CANARY}",
            "tool_name": f"tool-{SYNTHETIC_CANARY}",
            "resource": f"resource-{SYNTHETIC_CANARY}",
            "destination": f"destination-{SYNTHETIC_CANARY}",
            "arguments_redacted": {
                "payload": {"nested": [SYNTHETIC_CANARY]},
            },
            "outcome": f"outcome-{SYNTHETIC_CANARY}",
            "message": f"message-{SYNTHETIC_CANARY}",
        }
    )
    vulnerable = vulnerable.model_copy(
        update={
            "session_id": f"session-{SYNTHETIC_CANARY}",
            "fixture_id": f"fixture-{SYNTHETIC_CANARY}",
            "provider": f"provider-{SYNTHETIC_CANARY}",
            "status": f"status-{SYNTHETIC_CANARY}",
            "test_output": f"output-{SYNTHETIC_CANARY}",
            "events": [poisoned_event],
        }
    )
    policy = policy.model_copy(
        update={
            "id": f"policy-{SYNTHETIC_CANARY}",
            "evidence_event_ids": [f"event-{SYNTHETIC_CANARY}"],
            "yaml": f"policy: {SYNTHETIC_CANARY}",
        }
    )
    manifest = manifest.model_copy(
        update={
            "policy_id": f"policy-{SYNTHETIC_CANARY}",
            "digest_sha256": f"digest-{SYNTHETIC_CANARY}",
        }
    )

    rows = mirror_rows(vulnerable, replay, policy, manifest)

    assert tuple(rows) == TABLE_ORDER
    assert all(
        set(row) == ROW_KEYS[table]
        for table, table_rows in rows.items()
        for row in table_rows
    )
    assert all(SYNTHETIC_CANARY not in value for value in _all_strings(rows))
    assert {"arguments", "arguments_redacted", "test_output", "payload"}.isdisjoint(
        _all_keys(rows)
    )
    policy_storage_id = f"policy-[REDACTED]:{policy.policy_hash}"
    assert rows["policies"][0]["id"] == policy_storage_id
    assert rows["replays"][0]["policy_id"] == policy_storage_id

    schema = Path("supabase/schema.sql").read_text()
    assert {
        table: _sql_columns(schema, table) - {"created_at"}
        for table in TABLE_ORDER
    } == ROW_KEYS


def test_client_creation_uses_secret_key_and_stays_unverified(monkeypatch) -> None:
    created_with: list[tuple[str, str]] = []
    client = object()

    def create_client(url: str, key: str):
        created_with.append((url, key))
        return client

    monkeypatch.setenv("CUTLINE_SUPABASE_ENABLED", "1")
    monkeypatch.setenv("SUPABASE_URL", "https://synthetic.invalid")
    monkeypatch.setenv("SUPABASE_SECRET_KEY", "synthetic-secret-key")
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "must-not-be-used")
    monkeypatch.setitem(sys.modules, "supabase", SimpleNamespace(create_client=create_client))

    status = SupabaseMirror().status()

    assert created_with == [("https://synthetic.invalid", "synthetic-secret-key")]
    assert status == {
        "provider": "supabase",
        "state": "unverified",
        "configured": True,
        "last_checked_at": None,
        "message": "Run one mirror write to verify Supabase.",
    }


def test_legacy_service_role_key_does_not_configure_client(monkeypatch) -> None:
    monkeypatch.setenv("CUTLINE_SUPABASE_ENABLED", "1")
    monkeypatch.setenv("SUPABASE_URL", "https://synthetic.invalid")
    monkeypatch.delenv("SUPABASE_SECRET_KEY", raising=False)
    monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "must-not-be-used")

    status = SupabaseMirror().status()

    assert status["state"] == "error"
    assert status["configured"] is False
    assert "SUPABASE_SECRET_KEY" in status["message"]
    assert status["last_checked_at"] is not None


def test_success_bulk_upserts_exactly_five_tables_then_becomes_ready(
    monkeypatch, replay_bundle
) -> None:
    calls: list[tuple[str, list[dict[str, Any]]]] = []

    class Table:
        def __init__(self, name: str) -> None:
            self.name = name

        def upsert(self, rows: list[dict[str, Any]]):
            calls.append((self.name, rows))
            return self

        def execute(self) -> None:
            return None

    class Client:
        def table(self, name: str) -> Table:
            return Table(name)

    monkeypatch.setenv("CUTLINE_SUPABASE_ENABLED", "1")
    vulnerable, replay, policy, manifest = replay_bundle
    expected = mirror_rows(vulnerable, replay, policy, manifest)
    mirror = SupabaseMirror(client=Client())

    mirror.persist(vulnerable, replay, policy, manifest)

    assert calls == [
        (f"cutline_{table}", expected[table])
        for table in TABLE_ORDER
    ]
    assert mirror.status() == {
        "provider": "supabase",
        "state": "ready",
        "configured": True,
        "last_checked_at": mirror.last_checked_at,
        "message": None,
    }
    assert mirror.last_checked_at is not None


def test_failed_write_is_timestamped_and_successful_retry_clears_error(
    monkeypatch, replay_bundle
) -> None:
    class Table:
        def __init__(self, client) -> None:
            self.client = client

        def upsert(self, _rows):
            return self

        def execute(self) -> None:
            if self.client.fail:
                raise RuntimeError(f"provider leaked {SYNTHETIC_CANARY}")

    class Client:
        fail = True

        def table(self, _name: str) -> Table:
            return Table(self)

    monkeypatch.setenv("CUTLINE_SUPABASE_ENABLED", "1")
    vulnerable, replay, policy, manifest = replay_bundle
    client = Client()
    mirror = SupabaseMirror(client=client)

    mirror.persist(vulnerable, replay, policy, manifest)
    failed_at = mirror.last_checked_at

    assert failed_at is not None
    assert mirror.status() == {
        "provider": "supabase",
        "state": "error",
        "configured": True,
        "last_checked_at": failed_at,
        "message": "Supabase mirror write failed.",
    }
    assert SYNTHETIC_CANARY not in str(mirror.status())

    client.fail = False
    mirror.persist(vulnerable, replay, policy, manifest)

    assert mirror.status()["state"] == "ready"
    assert mirror.status()["message"] is None
    assert mirror.error is None
    assert mirror.last_checked_at is not None
    assert mirror.last_checked_at >= failed_at


def test_schema_and_migration_lock_down_every_browser_table() -> None:
    schema = Path("supabase/schema.sql").read_text().lower()
    migration = Path(
        "supabase/migrations/20260801_provider_contract.sql"
    ).read_text().lower()

    assert "source_type text not null" in schema
    assert "add column if not exists source_type" in migration
    for table in TABLE_ORDER:
        qualified_table = f"public.cutline_{table}"
        assert f"alter table {qualified_table} enable row level security;" in schema
        assert f"alter table {qualified_table} enable row level security;" in migration
        assert f"revoke all on table {qualified_table} from anon, authenticated;" in schema
        assert f"revoke all on table {qualified_table} from anon, authenticated;" in migration
    assert "create policy" not in schema
    assert "create policy" not in migration
