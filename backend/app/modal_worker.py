from __future__ import annotations

import argparse

from app.models import RunMode
from app.runner import AgentRunner

SENTINEL = "CUTLINE_RESULT="


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=[mode.value for mode in RunMode], required=True)
    args = parser.parse_args()

    result = AgentRunner(provider="modal-sandbox").run(RunMode(args.mode))
    print(f"{SENTINEL}{result.model_dump_json()}")


if __name__ == "__main__":
    main()
