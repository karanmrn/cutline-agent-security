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
from app.runner import SYNTHETIC_CANARY, AgentRunner

TABLE_ORDER = (
    "sessions",
    "events",
    "incidents",
    "policies",
    "replays",
)
SQL_TABLE_PREFIX = "cutline_safe_"
ROW_KEYS = {
    "sessions": {
        "run_id",
        "mode",
        "provider",
        "status",
        "secret_exposed",
        "exfiltration_attempted",
        "exfiltration_blocked",
        "code_fixed",
        "tests_passed",
        "collector_count",
    },
    "events": {
        "event_id",
        "run_id",
        "sequence_number",
        "parent_event_id",
        "source_trust",
        "data_class",
        "action_type",
        "policy_decision",
        "tool_category",
        "outcome",
    },
    "incidents": {
        "incident_id",
        "source_run_id",
        "secret_exposed",
        "exfiltration_attempted",
        "evidence_event_ids",
    },
    "policies": {
        "id",
        "version",
        "policy_hash",
        "effect",
        "disruption_score",
        "evidence_event_ids",
    },
    "replays": {
        "run_id",
        "policy_id",
        "blocked",
        "utility_retained",
        "tests_passed",
    },
}


@pytest.fixture
def replay_bundle():
    vulnerable = AgentRunner().run(RunMode.MONITOR)
    policy = build_policy(vulnerable.events)
    replay = AgentRunner().run(RunMode.ENFORCE, policy=policy)
    return vulnerable, replay, policy


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
        rf"create table if not exists public\.{SQL_TABLE_PREFIX}{table}\s*\((.*?)\n\);",
        sql,
        flags=re.DOTALL | re.IGNORECASE,
    )
    assert match is not None
    return {
        line.strip().split(maxsplit=1)[0]
        for line in match.group(1).splitlines()
        if line.strip()
    }


def test_rows_match_fixed_schema_and_exclude_free_text(replay_bundle) -> None:
    vulnerable, replay, policy = replay_bundle
    poisoned_event = vulnerable.events[0].model_copy(
        update={
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
            "yaml": f"policy: {SYNTHETIC_CANARY}",
        }
    )
    rows = mirror_rows(vulnerable, replay, policy)

    assert tuple(rows) == TABLE_ORDER
    assert all(
        set(row) == ROW_KEYS[table]
        for table, table_rows in rows.items()
        for row in table_rows
    )
    serialized = str(rows)
    assert SYNTHETIC_CANARY not in serialized
    assert {
        "actor",
        "arguments",
        "arguments_redacted",
        "destination",
        "digest_sha256",
        "fixture_id",
        "message",
        "payload",
        "policy_yaml",
        "resource",
        "session_id",
        "source_type",
        "test_output",
        "tool_name",
    }.isdisjoint(_all_keys(rows))
    policy_storage_id = f"cutline_policy_{policy.policy_hash}"
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


def test_client_initialization_recovers_after_credentials_are_added(monkeypatch) -> None:
    created_with: list[tuple[str, str]] = []
    client = object()

    def create_client(url: str, key: str):
        created_with.append((url, key))
        return client

    monkeypatch.setenv("CUTLINE_SUPABASE_ENABLED", "1")
    monkeypatch.delenv("SUPABASE_URL", raising=False)
    monkeypatch.delenv("SUPABASE_SECRET_KEY", raising=False)
    mirror = SupabaseMirror()

    assert mirror.status()["state"] == "error"

    monkeypatch.setenv("SUPABASE_URL", "https://synthetic.invalid")
    monkeypatch.setenv("SUPABASE_SECRET_KEY", "synthetic-secret-key")
    monkeypatch.setitem(sys.modules, "supabase", SimpleNamespace(create_client=create_client))

    recovered = mirror.status()

    assert created_with == [("https://synthetic.invalid", "synthetic-secret-key")]
    assert recovered["state"] == "unverified"
    assert recovered["configured"] is True
    assert recovered["message"] == "Run one mirror write to verify Supabase."


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
    vulnerable, replay, policy = replay_bundle
    expected = mirror_rows(vulnerable, replay, policy)
    mirror = SupabaseMirror(client=Client())

    mirror.persist(vulnerable, replay, policy)

    assert calls == [
        (f"{SQL_TABLE_PREFIX}{table}", expected[table])
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
    vulnerable, replay, policy = replay_bundle
    client = Client()
    mirror = SupabaseMirror(client=client)

    mirror.persist(vulnerable, replay, policy)
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
    mirror.persist(vulnerable, replay, policy)

    assert mirror.status()["state"] == "ready"
    assert mirror.status()["message"] is None
    assert mirror.error is None
    assert mirror.last_checked_at is not None
    assert mirror.last_checked_at >= failed_at


def test_schema_and_migration_lock_down_every_browser_table() -> None:
    schema = Path("supabase/schema.sql").read_text().lower()
    migration = Path(
        "supabase/migrations/20260801_safe_projection.sql"
    ).read_text().lower()
    normalized_migration = " ".join(migration.split())

    assert "source_type" not in schema
    assert "source_type" not in migration
    assert "message text" not in schema
    assert "policy_yaml" not in schema
    assert "drop table" not in migration
    for table in TABLE_ORDER:
        qualified_table = f"public.{SQL_TABLE_PREFIX}{table}"
        assert f"create table if not exists {qualified_table}" in normalized_migration
        assert f"alter table {qualified_table} enable row level security;" in schema
        assert f"alter table {qualified_table} enable row level security;" in migration
        assert f"revoke all on table {qualified_table} from anon, authenticated;" in schema
        assert f"revoke all on table {qualified_table} from anon, authenticated;" in migration
    assert "create policy" not in schema
    assert "create policy" not in migration
