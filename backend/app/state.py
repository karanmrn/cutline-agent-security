from __future__ import annotations

import os
from datetime import UTC, datetime
from threading import Lock

from app.integrations.overmind_trace import status as overmind_status
from app.integrations.supabase_store import mirror as supabase_mirror
from app.models import (
    DemoState,
    Incident,
    IntegrationState,
    IntegrationStatus,
    ProposedPolicy,
    RegressionManifest,
    RunResult,
)


def _status(
    provider: str,
    state: IntegrationState,
    configured: bool,
    message: str | None,
    *,
    checked_at: datetime | None = None,
) -> IntegrationStatus:
    return IntegrationStatus(
        provider=provider,
        state=state,
        configured=configured,
        last_checked_at=checked_at,
        message=message,
    )


class DemoStore:
    def __init__(self) -> None:
        self._lock = Lock()
        self._vulnerable_run: RunResult | None = None
        self._incident: Incident | None = None
        self._proposed_policy: ProposedPolicy | None = None
        self._replay_run: RunResult | None = None
        self._regression_manifest: RegressionManifest | None = None
        self._integration_overrides: dict[str, IntegrationStatus] = {}

    def reset(self) -> DemoState:
        with self._lock:
            self._vulnerable_run = None
            self._incident = None
            self._proposed_policy = None
            self._replay_run = None
            self._regression_manifest = None
            return self.snapshot()

    def set_vulnerable(self, run: RunResult) -> None:
        with self._lock:
            self._vulnerable_run = run
            self._incident = None
            self._proposed_policy = None
            self._replay_run = None
            self._regression_manifest = None

    def set_policy(self, policy: ProposedPolicy) -> None:
        with self._lock:
            self._proposed_policy = policy

    def set_incident(self, incident: Incident) -> None:
        with self._lock:
            self._incident = incident

    def set_replay(self, run: RunResult, manifest: RegressionManifest) -> None:
        with self._lock:
            self._replay_run = run
            self._regression_manifest = manifest

    def set_integration_ready(self, name: str) -> None:
        with self._lock:
            self._integration_overrides[name] = _status(
                name,
                IntegrationState.READY,
                True,
                None,
                checked_at=datetime.now(UTC),
            )

    def set_integration_error(self, name: str, error: str) -> None:
        with self._lock:
            self._integration_overrides[name] = _status(
                name,
                IntegrationState.ERROR,
                True,
                error,
                checked_at=datetime.now(UTC),
            )

    def set_integration_status(self, status: IntegrationStatus) -> None:
        with self._lock:
            self._integration_overrides[status.provider] = status

    def snapshot(self) -> DemoState:
        modal_enabled = os.getenv("CUTLINE_MODAL_ENABLED") == "1"
        integrations: dict[str, IntegrationStatus] = {
            "local": _status("local", IntegrationState.READY, True, None),
            "modal": _status(
                "modal",
                IntegrationState.UNVERIFIED,
                modal_enabled,
                "Run one network-blocked replay to verify this provider."
                if modal_enabled
                else "Set CUTLINE_MODAL_ENABLED=1 after Modal setup.",
            ),
            "overmind": _status(
                "overmind",
                IntegrationState.DISABLED,
                False,
                "Set CUTLINE_OVERMIND_ENABLED=1 after configuring Overmind.",
            ),
            "supabase": _status(
                "supabase",
                IntegrationState.DISABLED,
                False,
                "Set CUTLINE_SUPABASE_ENABLED=1 after configuring Supabase.",
            ),
            "ossprey": _status(
                "ossprey",
                IntegrationState.DISABLED,
                False,
                "Enable only after sponsor staff provide a documented integration path.",
            ),
        }
        if os.getenv("CUTLINE_OVERMIND_ENABLED") == "1":
            integrations["overmind"] = IntegrationStatus.model_validate(overmind_status())
        if os.getenv("CUTLINE_SUPABASE_ENABLED") == "1":
            integrations["supabase"] = IntegrationStatus.model_validate(
                supabase_mirror.status()
            )
        integrations.update(self._integration_overrides)
        return DemoState(
            vulnerable_run=self._vulnerable_run,
            incident=self._incident,
            proposed_policy=self._proposed_policy,
            replay_run=self._replay_run,
            regression_manifest=self._regression_manifest,
            integrations=integrations,
        )


store = DemoStore()
