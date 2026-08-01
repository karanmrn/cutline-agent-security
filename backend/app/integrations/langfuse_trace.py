from __future__ import annotations

import os
from importlib import import_module
from typing import Any

from app.integrations.safe_projection import SafeRun, SafeToolCategory

_client: Any | None = None
_initialization_attempted = False
_state = "unverified"
_message = "Run one trace to initialize Langfuse."

_EVENT_OBSERVATIONS = {
    SafeToolCategory.TASK: ("task", "span"),
    SafeToolCategory.INSTRUCTION_READ: ("instruction-read", "retriever"),
    SafeToolCategory.FILE_READ: ("file-read", "retriever"),
    SafeToolCategory.EXTERNAL_WRITE: ("external-write", "tool"),
    SafeToolCategory.FILE_WRITE: ("file-write", "tool"),
    SafeToolCategory.TEST_RUN: ("test-run", "tool"),
    SafeToolCategory.UNKNOWN: ("unknown-event", "span"),
}


def _enabled() -> bool:
    return os.getenv("CUTLINE_LANGFUSE_ENABLED") == "1"


def _configuration() -> tuple[str, str, str] | None:
    public_key = os.getenv("LANGFUSE_PUBLIC_KEY")
    secret_key = os.getenv("LANGFUSE_SECRET_KEY")
    base_url = os.getenv("LANGFUSE_BASE_URL")
    if not public_key or not secret_key or not base_url:
        return None
    return public_key, secret_key, base_url


def _set_error(message: str) -> None:
    global _message, _state
    _state = "error"
    _message = message


def _get_client() -> Any | None:
    global _client, _initialization_attempted, _message, _state
    if not _enabled():
        return None

    configuration = _configuration()
    if configuration is None:
        _set_error("Langfuse configuration is incomplete.")
        return None
    if _initialization_attempted:
        return _client

    _initialization_attempted = True
    public_key, _secret_key, _base_url = configuration
    try:
        get_client = import_module("langfuse").get_client
        _client = get_client(public_key=public_key)
    except Exception:  # noqa: BLE001 - optional telemetry cannot fail local runs
        _set_error("Langfuse client initialization failed.")
        return None

    _state = "unverified"
    _message = "Langfuse client initialized; no telemetry flush completed."
    return _client


def trace_run(run: SafeRun) -> None:
    global _message, _state
    client = _get_client()
    if client is None:
        return

    try:
        with client.start_as_current_observation(
            name="cutline-run", as_type="agent"
        ), client.start_as_current_observation(
            name="fix-and-verify", as_type="chain"
        ):
            for event in run.events:
                name, observation_type = _EVENT_OBSERVATIONS[event.tool_category]
                with client.start_as_current_observation(
                    name=name, as_type=observation_type
                ):
                    pass
    except Exception:  # noqa: BLE001 - optional telemetry cannot fail local runs
        _set_error("Langfuse observation failed.")
        return

    try:
        client.flush()
    except Exception:  # noqa: BLE001 - optional telemetry cannot fail local runs
        _set_error("Langfuse telemetry flush failed.")
        return

    _state = "ready"
    _message = "Telemetry flush completed; provider ingestion remains unverified."


def status() -> dict[str, Any]:
    if not _enabled():
        return {
            "provider": "langfuse",
            "state": "disabled",
            "configured": False,
            "last_checked_at": None,
            "message": "Set CUTLINE_LANGFUSE_ENABLED=1 after configuring Langfuse.",
        }
    if _configuration() is None:
        return {
            "provider": "langfuse",
            "state": "error",
            "configured": False,
            "last_checked_at": None,
            "message": "Langfuse configuration is incomplete.",
        }
    return {
        "provider": "langfuse",
        "state": _state,
        "configured": True,
        "last_checked_at": None,
        "message": _message,
    }
