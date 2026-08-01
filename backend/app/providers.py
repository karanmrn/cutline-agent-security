from __future__ import annotations

import os
from typing import Protocol

from app.models import ExecutionProvider, ProposedPolicy, RunMode, RunResult
from app.runner import AgentRunner


class ReplayProvider(Protocol):
    name: ExecutionProvider

    def replay(self, policy: ProposedPolicy) -> RunResult: ...


class ProviderUnavailable(RuntimeError):
    pass


class LocalReplayProvider:
    name = ExecutionProvider.LOCAL

    def replay(self, policy: ProposedPolicy) -> RunResult:
        return AgentRunner(provider=self.name.value).run(RunMode.ENFORCE, policy=policy)


class ModalReplayProvider:
    name = ExecutionProvider.MODAL

    def replay(self, policy: ProposedPolicy) -> RunResult:
        if os.getenv("CUTLINE_MODAL_ENABLED") != "1":
            raise ProviderUnavailable(
                "Modal replay is disabled. Set CUTLINE_MODAL_ENABLED=1 after setup."
            )
        try:
            from modal_sandbox import run_in_modal

            return run_in_modal(RunMode.ENFORCE, policy=policy)
        except Exception as exc:
            raise ProviderUnavailable(f"Modal replay failed: {exc}") from exc


def get_replay_provider(provider: ExecutionProvider) -> ReplayProvider:
    if provider == ExecutionProvider.LOCAL:
        return LocalReplayProvider()
    return ModalReplayProvider()
