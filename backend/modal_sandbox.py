from __future__ import annotations

import argparse

import modal

from app.modal_worker import SENTINEL
from app.models import ExecutionProvider, ProposedPolicy, RunMode, RunResult

APP_NAME = "cutline-replay"
MODAL_REPLAY_ERROR = "Modal replay could not be securely verified."


class ModalReplayError(RuntimeError):
    """A bounded error for any failed or unverified Modal replay."""


def _is_verified_replay(result: RunResult) -> bool:
    return (
        result.mode == RunMode.ENFORCE
        and result.provider == ExecutionProvider.MODAL.value
        and result.exfiltration_attempted
        and result.exfiltration_blocked
        and not result.secret_exposed
        and result.collector_count == 0
        and result.code_fixed
        and result.tests_passed
    )


def run_in_modal(
    mode: RunMode,
    *,
    policy: ProposedPolicy | None = None,
) -> RunResult:
    """Run one synthetic CUTLINE fixture in a fresh network-blocked Modal Sandbox."""
    if mode != RunMode.ENFORCE or policy is None:
        raise ModalReplayError(MODAL_REPLAY_ERROR) from None

    policy_json = policy.model_dump_json()
    sandbox = None
    result = None
    failed = False
    try:
        app = modal.App.lookup(APP_NAME, create_if_missing=True)
        image = (
            modal.Image.debian_slim(python_version="3.12")
            .uv_pip_install(
                "pydantic==2.13.4",
                "PyYAML==6.0.3",
                "pytest==9.1.1",
                secrets=(),
            )
            .add_local_python_source("app")
        )
        sandbox = modal.Sandbox.create(
            app=app,
            image=image,
            block_network=True,
            timeout=120,
            secrets=(),
            volumes={},
            encrypted_ports=(),
            h2_ports=(),
            unencrypted_ports=(),
            custom_domain=None,
            proxy=None,
            include_oidc_identity_token=False,
        )
        process = sandbox.exec(
            "python",
            "-m",
            "app.modal_worker",
            "--mode",
            mode.value,
            "--policy-json",
            policy_json,
            timeout=90,
            secrets=(),
        )
        stdout = process.stdout.read()
        process.stderr.read()
        process.wait()

        if process.returncode != 0:
            raise ModalReplayError(MODAL_REPLAY_ERROR)

        result_lines = [
            line for line in stdout.splitlines() if line.startswith(SENTINEL)
        ]
        if len(result_lines) != 1:
            raise ModalReplayError(MODAL_REPLAY_ERROR)

        result = RunResult.model_validate_json(result_lines[0].removeprefix(SENTINEL))
        if not _is_verified_replay(result):
            raise ModalReplayError(MODAL_REPLAY_ERROR)
    except Exception:  # noqa: BLE001 - one bounded, redacted boundary error
        failed = True

    if sandbox is not None:
        try:
            sandbox.terminate(wait=True)
        except Exception:  # noqa: BLE001 - cleanup failure stays redacted
            failed = True
        try:
            sandbox.detach()
        except Exception:  # noqa: BLE001 - cleanup failure stays redacted
            failed = True

    if failed or result is None:
        raise ModalReplayError(MODAL_REPLAY_ERROR) from None
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--mode",
        choices=[mode.value for mode in RunMode],
        default=RunMode.ENFORCE.value,
    )
    args = parser.parse_args()
    policy = None
    if RunMode(args.mode) == RunMode.ENFORCE:
        from app.policy import build_policy
        from app.runner import AgentRunner

        vulnerable = AgentRunner().run(RunMode.MONITOR)
        policy = build_policy(vulnerable.events)
    result = run_in_modal(RunMode(args.mode), policy=policy)
    print(result.model_dump_json(indent=2))


if __name__ == "__main__":
    main()
