from __future__ import annotations

import os
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from app.integrations.safe_projection import SafeEvent, SafeRun, project_run
from app.models import ProposedPolicy, RunResult
from app.runner import SYNTHETIC_CANARY

SQL_TABLE_PREFIX = "cutline_safe_"


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


def _run_id(run: SafeRun) -> str:
    digest = sha256(run.model_dump_json().encode()).hexdigest()[:16]
    return f"cutline_run_{digest}"


def _session_row(run: SafeRun, run_id: str) -> dict[str, Any]:
    return {
        "run_id": run_id,
        "mode": run.mode.value,
        "provider": run.provider.value,
        "status": run.status.value,
        "secret_exposed": run.secret_exposed,
        "exfiltration_attempted": run.exfiltration_attempted,
        "exfiltration_blocked": run.exfiltration_blocked,
        "code_fixed": run.code_fixed,
        "tests_passed": run.tests_passed,
        "collector_count": run.collector_count,
    }


def _event_row(event: SafeEvent, run_id: str) -> dict[str, Any]:
    return {
        "event_id": event.event_id,
        "run_id": run_id,
        "sequence_number": event.sequence_number,
        "parent_event_id": event.parent_event_id,
        "source_trust": event.source_trust.value,
        "data_class": event.data_class.value,
        "action_type": event.action_type.value,
        "policy_decision": event.policy_decision.value,
        "tool_category": event.tool_category.value,
        "outcome": event.outcome.value,
    }


def mirror_rows(
    vulnerable: RunResult,
    replay: RunResult,
    policy: ProposedPolicy,
) -> dict[str, list[dict[str, Any]]]:
    safe_vulnerable = project_run(vulnerable)
    safe_replay = project_run(replay)
    vulnerable_run_id = _run_id(safe_vulnerable)
    replay_run_id = _run_id(safe_replay)
    allowed_evidence_ids = {event.event_id for event in safe_vulnerable.events}
    evidence_event_ids = [
        event_id
        for event_id in policy.evidence_event_ids
        if event_id in allowed_evidence_ids
    ]
    policy_storage_id = f"cutline_policy_{policy.policy_hash}"
    rows = {
        "sessions": [
            _session_row(safe_vulnerable, vulnerable_run_id),
            _session_row(safe_replay, replay_run_id),
        ],
        "events": [
            *(
                _event_row(event, vulnerable_run_id)
                for event in safe_vulnerable.events
            ),
            *(_event_row(event, replay_run_id) for event in safe_replay.events),
        ],
        "incidents": [
            {
                "incident_id": (
                    "cutline_incident_"
                    f"{vulnerable_run_id.removeprefix('cutline_run_')}"
                ),
                "source_run_id": vulnerable_run_id,
                "secret_exposed": safe_vulnerable.secret_exposed,
                "exfiltration_attempted": safe_vulnerable.exfiltration_attempted,
                "evidence_event_ids": evidence_event_ids,
            }
        ],
        "policies": [
            {
                "id": policy_storage_id,
                "version": policy.version,
                "policy_hash": policy.policy_hash,
                "effect": policy.effect.value,
                "disruption_score": policy.disruption_score,
                "evidence_event_ids": evidence_event_ids,
            }
        ],
        "replays": [
            {
                "run_id": replay_run_id,
                "policy_id": policy_storage_id,
                "blocked": safe_replay.exfiltration_blocked,
                "utility_retained": safe_replay.code_fixed,
                "tests_passed": safe_replay.tests_passed,
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
        self._verified = False

    def _record_error(self, message: str) -> None:
        self._verified = False
        self.error = message
        self.last_checked_at = datetime.now(UTC)

    def _ensure_client(self) -> Any | None:
        if os.getenv("CUTLINE_SUPABASE_ENABLED") != "1":
            return None
        if self.client is not None:
            return self.client
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
            self.error = None
        except Exception:  # pragma: no cover - optional integration  # noqa: BLE001
            self._record_error("Supabase client unavailable.")
        return self.client

    def persist(
        self,
        vulnerable: RunResult,
        replay: RunResult,
        policy: ProposedPolicy,
    ) -> None:
        client = self._ensure_client()
        if client is None:
            return
        rows = mirror_rows(vulnerable, replay, policy)
        self.error = None
        self._verified = False
        try:
            for table, table_rows in rows.items():
                client.table(f"{SQL_TABLE_PREFIX}{table}").upsert(table_rows).execute()
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
