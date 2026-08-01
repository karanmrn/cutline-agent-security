from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any, TypeVar

F = TypeVar("F", bound=Callable[..., Any])

ENABLED = False
_IMPORT_ERROR: str | None = None


def _identity_decorator(_name: str) -> Callable[[F], F]:
    def decorate(func: F) -> F:
        return func

    return decorate


entry_point = _identity_decorator
workflow = _identity_decorator
tool = _identity_decorator


if os.getenv("OVERMIND_API_KEY"):
    try:
        from overmind import (  # type: ignore[assignment]
            entry_point as _entry_point,
            init,
            set_agent_name,
            tool as _tool,
            workflow as _workflow,
        )

        init(
            service_name="cutline-agent-security",
            environment=os.getenv("CUTLINE_ENVIRONMENT", "hackathon"),
            providers=[],
        )
        set_agent_name("CUTLINE Incident Replay")
        entry_point = _entry_point
        workflow = _workflow
        tool = _tool
        ENABLED = True
    except Exception as exc:  # pragma: no cover - optional integration
        _IMPORT_ERROR = str(exc)


def status() -> dict[str, Any]:
    return {
        "enabled": ENABLED,
        "configured": bool(os.getenv("OVERMIND_API_KEY")),
        "error": _IMPORT_ERROR,
    }
