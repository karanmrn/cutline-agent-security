from __future__ import annotations

import os
import subprocess
import tempfile
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Never

_ENABLED_ENV = "CUTLINE_OSSPREY_ENABLED"
_EXECUTABLE_ENV = "CUTLINE_OSSPREY_EXECUTABLE"
_SCAN_TIMEOUT_SECONDS = 10
_SYNTHETIC_FIXTURE = (
    '# Synthetic local-only scanner fixture.\nCANARY = "CUTLINE_CANARY_7F3A"\n'
)

_state = "unverified"
_last_checked_at: datetime | None = None
_message = "Run one local safe scan to verify Ossprey."


class OsspreyErrorCategory(StrEnum):
    CONFIGURATION = "configuration"
    LAUNCH = "launch"
    TIMEOUT = "timeout"
    SCAN_FAILED = "scan_failed"
    OUTPUT_MISSING = "output_missing"
    UNSAFE_TEMPORARY_DIRECTORY = "unsafe_temporary_directory"


_ERROR_MESSAGES = {
    OsspreyErrorCategory.CONFIGURATION: "Ossprey executable is not configured.",
    OsspreyErrorCategory.LAUNCH: "Ossprey scan could not start.",
    OsspreyErrorCategory.TIMEOUT: "Ossprey scan timed out.",
    OsspreyErrorCategory.SCAN_FAILED: "Ossprey scan failed.",
    OsspreyErrorCategory.OUTPUT_MISSING: "Ossprey scan output is missing.",
    OsspreyErrorCategory.UNSAFE_TEMPORARY_DIRECTORY: (
        "Ossprey temporary scan location is unsafe."
    ),
}


class OsspreyScanError(RuntimeError):
    def __init__(self, category: OsspreyErrorCategory) -> None:
        self.category = category
        super().__init__(_ERROR_MESSAGES[category])


def _enabled() -> bool:
    return os.getenv(_ENABLED_ENV) == "1"


def _explicit_executable() -> str | None:
    executable = os.getenv(_EXECUTABLE_ENV)
    if not executable or not Path(executable).is_absolute():
        return None
    return executable


def _record_error(error: OsspreyScanError) -> None:
    global _last_checked_at, _message, _state
    _state = "error"
    _last_checked_at = datetime.now(UTC)
    _message = str(error)


def _raise_error(category: OsspreyErrorCategory) -> Never:
    error = OsspreyScanError(category)
    _record_error(error)
    raise error


def verify_synthetic_fixture() -> None:
    """Run Ossprey's documented local safe scan against a disposable fixture."""
    global _last_checked_at, _message, _state

    if not _enabled():
        return

    executable = _explicit_executable()
    if executable is None:
        _raise_error(OsspreyErrorCategory.CONFIGURATION)

    with tempfile.TemporaryDirectory(prefix="cutline-ossprey-") as temp_dir:
        temporary_directory = Path(temp_dir)
        resolved_directory = temporary_directory.resolve()
        unsafe_roots = (Path.cwd().resolve(), Path.home().resolve())
        if any(
            resolved_directory == root or root in resolved_directory.parents
            for root in unsafe_roots
        ):
            _raise_error(OsspreyErrorCategory.UNSAFE_TEMPORARY_DIRECTORY)

        fixture = temporary_directory / "synthetic_fixture.py"
        output = temporary_directory / "ossprey-output.json"
        fixture.write_text(_SYNTHETIC_FIXTURE, encoding="utf-8")

        child_environment = {
            "HOME": temp_dir,
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "",
            "TMPDIR": temp_dir,
        }
        command = [
            executable,
            "scan",
            str(fixture),
            "--local",
            "--dry-run-safe",
            "-o",
            str(output),
        ]
        try:
            completed = subprocess.run(
                command,
                check=False,
                cwd=temp_dir,
                env=child_environment,
                shell=False,
                stdin=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                text=True,
                timeout=_SCAN_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired:
            _raise_error(OsspreyErrorCategory.TIMEOUT)
        except OSError:
            _raise_error(OsspreyErrorCategory.LAUNCH)

        if completed.returncode != 0:
            _raise_error(OsspreyErrorCategory.SCAN_FAILED)
        if not output.is_file():
            _raise_error(OsspreyErrorCategory.OUTPUT_MISSING)

    _state = "ready"
    _last_checked_at = datetime.now(UTC)
    _message = "Local safe scan completed."


def status() -> dict[str, Any]:
    if not _enabled():
        return {
            "provider": "ossprey",
            "state": "disabled",
            "configured": False,
            "last_checked_at": None,
            "message": "Set CUTLINE_OSSPREY_ENABLED=1 with an explicit executable.",
        }

    configured = _explicit_executable() is not None
    if not configured:
        return {
            "provider": "ossprey",
            "state": "error",
            "configured": False,
            "last_checked_at": _last_checked_at,
            "message": _ERROR_MESSAGES[OsspreyErrorCategory.CONFIGURATION],
        }

    return {
        "provider": "ossprey",
        "state": _state,
        "configured": True,
        "last_checked_at": _last_checked_at,
        "message": _message,
    }
