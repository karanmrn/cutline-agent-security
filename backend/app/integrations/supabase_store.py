from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any

from app.models import Event, ProposedPolicy, RegressionManifest, RunResult
from app.runner import SYNTHETIC_CANARY


def _redact_strings(value: Any) -> Any:
    if isinstance(value, str):
        return value.replace(SYNTHETIC_CANARY, "[REDACTED]")
    if isinstance(value, dict):
        return {
            _redact_strings(key): _redact_strings(nested_value)
            for key, nested_value in value.items()
        }
    if isinstance(value, list):
        return [_redact_strings(nested_value) for nested_value in value]
    if isinstance(value, tuple):
        return tuple(_redact_strings(nested_value) for nested_value in value)
    return value


def _session_row(run: RunResult) -> dict[str, Any]:
    return {
        "session_id": run.session_id,
        "fixture_id": run.fixture_id,
        "mode": run.mode.value,
        "provider": run.provider,
        "status": run.status,
        "secret_exposed": run.secret_exposed,
        "tests_passed": run.tests_passed,
    }


def _event_row(event: Event) -> dict[str, Any]:
    return {
        "event_id": event.event_id,
        "session_id": event.session_id,
        "sequence_number": event.sequence_number,
        "parent_event_id": event.parent_event_id,
        "actor": event.actor,
        "source_type": event.source_type,
        "source_trust": event.source_trust.value,
        "data_class": event.data_class.value,
        "tool_name": event.tool_name,
        "resource": event.resource,
        "destination": event.destination,
        "action_type": event.action_type.value,
        "policy_decision": event.policy_decision.value,
        "outcome": event.outcome,
        "message": event.message,
    }


def mirror_rows(
    vulnerable: RunResult,
    replay: RunResult,
    policy: ProposedPolicy,
    manifest: RegressionManifest,
) -> dict[str, list[dict[str, Any]]]:
    all_events = vulnerable.events + replay.events
    policy_storage_id = f"{policy.id}:{policy.policy_hash}"
    rows = {
        "sessions": [_session_row(vulnerable), _session_row(replay)],
        "events": [_event_row(event) for event in all_events],
        "incidents": [
            {
                "incident_id": f"incident_{vulnerable.session_id}",
                "source_session_id": vulnerable.session_id,
                "severity": "high",
                "summary": "Synthetic secret reached unauthorized external write in monitor mode.",
                "evidence_event_ids": policy.evidence_event_ids,
            }
        ],
        "policies": [
            {
                "id": policy_storage_id,
                "version": policy.version,
                "policy_hash": policy.policy_hash,
                "effect": policy.effect.value,
                "disruption_score": policy.disruption_score,
                "evidence_event_ids": policy.evidence_event_ids,
                "policy_yaml": policy.yaml,
            }
        ],
        "replays": [
            {
                "session_id": replay.session_id,
                "policy_id": policy_storage_id,
                "blocked": replay.exfiltration_blocked,
                "utility_retained": replay.code_fixed,
                "digest_sha256": manifest.digest_sha256,
            }
        ],
    }
    return _redact_strings(rows)


class SupabaseMirror:
    def __init__(self, client: Any | None = None) -> None:
        self.client = client
        self._configured = client is not None
        self.error: str | None = None
        self.last_checked_at: datetime | None = None
        self._initialization_attempted = client is not None
        self._verified = False

    def _record_error(self, message: str) -> None:
        self._verified = False
        self.error = message
        self.last_checked_at = datetime.now(UTC)

    def _ensure_client(self) -> Any | None:
        if os.getenv("CUTLINE_SUPABASE_ENABLED") != "1":
            return None
        if self._initialization_attempted:
            return self.client
        self._initialization_attempted = True
        url = os.getenv("SUPABASE_URL")
        key = os.getenv("SUPABASE_SECRET_KEY")
        self._configured = bool(url and key)
        if not url or not key:
            self._record_error(
                "SUPABASE_URL and SUPABASE_SECRET_KEY (server-side key) are required."
            )
            return None
        try:
            from supabase import create_client

            self.client = create_client(url, key)
        except Exception:  # pragma: no cover - optional integration  # noqa: BLE001
            self._record_error("Supabase client unavailable.")
        return self.client

    def persist(
        self,
        vulnerable: RunResult,
        replay: RunResult,
        policy: ProposedPolicy,
        manifest: RegressionManifest,
    ) -> None:
        client = self._ensure_client()
        if client is None:
            return
        rows = mirror_rows(vulnerable, replay, policy, manifest)
        self.error = None
        self._verified = False
        try:
            for table, table_rows in rows.items():
                client.table(f"cutline_{table}").upsert(table_rows).execute()
        except Exception:  # pragma: no cover - optional integration  # noqa: BLE001
            self._record_error("Supabase mirror write failed.")
            return
        self.last_checked_at = datetime.now(UTC)
        self._verified = True

    def status(self) -> dict[str, Any]:
        enabled = os.getenv("CUTLINE_SUPABASE_ENABLED") == "1"
        if not enabled:
            return {
                "provider": "supabase",
                "state": "disabled",
                "configured": False,
                "last_checked_at": None,
                "message": "Set CUTLINE_SUPABASE_ENABLED=1 after configuring Supabase.",
            }
        self._ensure_client()
        if self.error:
            return {
                "provider": "supabase",
                "state": "error",
                "configured": self._configured,
                "last_checked_at": self.last_checked_at,
                "message": self.error,
            }
        return {
            "provider": "supabase",
            "state": "ready" if self._verified else "unverified",
            "configured": self._configured,
            "last_checked_at": self.last_checked_at,
            "message": None
            if self._verified
            else "Run one mirror write to verify Supabase.",
        }


mirror = SupabaseMirror()
