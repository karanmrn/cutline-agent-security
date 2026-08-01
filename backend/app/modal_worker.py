from __future__ import annotations

import argparse

from app.models import ProposedPolicy, RunMode
from app.runner import AgentRunner

SENTINEL = "CUTLINE_RESULT="


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=[mode.value for mode in RunMode], required=True)
    parser.add_argument("--policy-json")
    args = parser.parse_args()

    policy = (
        ProposedPolicy.model_validate_json(args.policy_json)
        if args.policy_json
        else None
    )
    result = AgentRunner(provider="modal").run(RunMode(args.mode), policy=policy)
    print(f"{SENTINEL}{result.model_dump_json()}")


if __name__ == "__main__":
    main()
