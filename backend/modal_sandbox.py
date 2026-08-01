from __future__ import annotations

import argparse
import json
from typing import Any

import modal

from app.modal_worker import SENTINEL
from app.models import ProposedPolicy, RunMode, RunResult

APP_NAME = "cutline-replay"


def run_in_modal(
    mode: RunMode,
    *,
    policy: ProposedPolicy | None = None,
) -> RunResult:
    """Run one synthetic CUTLINE fixture in a fresh network-blocked Modal Sandbox."""
    app = modal.App.lookup(APP_NAME, create_if_missing=True)
    image = (
        modal.Image.debian_slim(python_version="3.12")
        .uv_pip_install(
            "pydantic>=2.10,<3",
            "pyyaml>=6,<7",
            "pytest>=8,<10",
        )
        .add_local_python_source("app")
    )

    sandbox = modal.Sandbox.create(
        app=app,
        image=image,
        block_network=True,
        timeout=120,
    )
    try:
        worker_args = [
            "python",
            "-m",
            "app.modal_worker",
            "--mode",
            mode.value,
        ]
        if policy:
            worker_args.extend(["--policy-json", policy.model_dump_json()])
        process = sandbox.exec(*worker_args, timeout=90)
        stdout = process.stdout.read()
        stderr = process.stderr.read()
        process.wait()

        if process.returncode != 0:
            raise RuntimeError(
                f"Modal worker failed with return code {process.returncode}: {stderr.strip()}"
            )

        result_line = next(
            (line for line in stdout.splitlines() if line.startswith(SENTINEL)),
            None,
        )
        if not result_line:
            raise RuntimeError(
                "Modal worker completed without a structured CUTLINE result. "
                f"stdout={stdout!r} stderr={stderr!r}"
            )

        payload: dict[str, Any] = json.loads(result_line.removeprefix(SENTINEL))
        return RunResult.model_validate(payload)
    finally:
        sandbox.terminate()


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
