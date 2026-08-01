from __future__ import annotations

from threading import Lock

from app.models import DemoState, ProposedPolicy, RunResult


class DemoStore:
    def __init__(self) -> None:
        self._lock = Lock()
        self._vulnerable_run: RunResult | None = None
        self._proposed_policy: ProposedPolicy | None = None
        self._replay_run: RunResult | None = None

    def reset(self) -> DemoState:
        with self._lock:
            self._vulnerable_run = None
            self._proposed_policy = None
            self._replay_run = None
            return self.snapshot()

    def set_vulnerable(self, run: RunResult) -> None:
        with self._lock:
            self._vulnerable_run = run
            self._proposed_policy = None
            self._replay_run = None

    def set_policy(self, policy: ProposedPolicy) -> None:
        with self._lock:
            self._proposed_policy = policy

    def set_replay(self, run: RunResult) -> None:
        with self._lock:
            self._replay_run = run

    def snapshot(self) -> DemoState:
        return DemoState(
            vulnerable_run=self._vulnerable_run,
            proposed_policy=self._proposed_policy,
            replay_run=self._replay_run,
            integrations={
                "local": {"enabled": True, "configured": True, "error": None},
                "modal": {
                    "enabled": False,
                    "configured": False,
                    "error": "Starter contains the implementation prompt, not a claimed live Modal integration.",
                },
                "overmind": {
                    "enabled": False,
                    "configured": False,
                    "error": "Disabled in the fully local demo.",
                },
                "supabase": {
                    "enabled": False,
                    "configured": False,
                    "error": "Disabled in the fully local demo.",
                },
                "ossprey": {
                    "enabled": False,
                    "configured": False,
                    "error": "Enable only when sponsor staff provide a documented integration path.",
                },
            },
        )


store = DemoStore()
