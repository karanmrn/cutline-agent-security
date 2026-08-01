from __future__ import annotations

import importlib
import shutil
import subprocess
from pathlib import Path

import pytest

from app.integrations import ossprey_scan as ossprey_scan_module
from app.models import ActionType, DataClass, PolicyDecision
from app.policy import evaluate_external_write


@pytest.fixture
def adapter(monkeypatch):
    monkeypatch.delenv("CUTLINE_OSSPREY_ENABLED", raising=False)
    monkeypatch.delenv("CUTLINE_OSSPREY_EXECUTABLE", raising=False)
    return importlib.reload(ossprey_scan_module)


def test_disabled_mode_never_resolves_or_launches_a_binary(
    adapter, monkeypatch
) -> None:
    def unexpected_call(*_args, **_kwargs):
        pytest.fail("disabled Ossprey adapter touched a process boundary")

    monkeypatch.setattr(shutil, "which", unexpected_call)
    monkeypatch.setattr(subprocess, "run", unexpected_call)

    assert adapter.verify_synthetic_fixture() is None
    assert adapter.status() == {
        "provider": "ossprey",
        "state": "disabled",
        "configured": False,
        "last_checked_at": None,
        "message": "Set CUTLINE_OSSPREY_ENABLED=1 with an explicit executable.",
    }


@pytest.mark.parametrize("executable", [None, "ossprey", "bin/ossprey"])
def test_enabled_mode_requires_an_explicit_absolute_executable(
    adapter, monkeypatch, executable
) -> None:
    monkeypatch.setenv("CUTLINE_OSSPREY_ENABLED", "1")
    if executable is not None:
        monkeypatch.setenv("CUTLINE_OSSPREY_EXECUTABLE", executable)

    def unexpected_run(*_args, **_kwargs):
        pytest.fail("invalid Ossprey configuration launched a process")

    monkeypatch.setattr(subprocess, "run", unexpected_run)

    with pytest.raises(adapter.OsspreyScanError) as error:
        adapter.verify_synthetic_fixture()

    assert error.value.category == "configuration"
    assert str(error.value) == "Ossprey executable is not configured."
    assert adapter.status()["state"] == "error"
    assert adapter.status()["configured"] is False


def test_safe_scan_uses_only_generated_temporary_files(adapter, monkeypatch) -> None:
    monkeypatch.setenv("CUTLINE_OSSPREY_ENABLED", "1")
    monkeypatch.setenv("CUTLINE_OSSPREY_EXECUTABLE", "/synthetic/bin/ossprey")
    workspace = Path.cwd().resolve()
    observed: dict[str, object] = {}

    def fake_run(argv, **kwargs):
        fixture = Path(argv[2])
        output = Path(argv[argv.index("-o") + 1])
        observed.update(argv=list(argv), fixture=fixture, output=output, kwargs=kwargs)

        assert fixture.is_file()
        assert fixture.read_text(encoding="utf-8") == (
            '# Synthetic local-only scanner fixture.\nCANARY = "CUTLINE_CANARY_7F3A"\n'
        )
        assert workspace not in fixture.resolve().parents
        assert Path.home().resolve() not in fixture.resolve().parents
        assert output.parent == fixture.parent
        assert not output.exists()
        assert kwargs["cwd"] == str(fixture.parent)
        assert kwargs["env"] == {
            "HOME": str(fixture.parent),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "",
            "TMPDIR": str(fixture.parent),
        }
        output.write_text("{}\n", encoding="utf-8")
        return subprocess.CompletedProcess(argv, 0, stdout="ignored", stderr="ignored")

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert adapter.status()["state"] == "unverified"
    assert adapter.verify_synthetic_fixture() is None

    assert observed["argv"] == [
        "/synthetic/bin/ossprey",
        "scan",
        str(observed["fixture"]),
        "--local",
        "--dry-run-safe",
        "-o",
        str(observed["output"]),
    ]
    assert observed["kwargs"] == {
        "check": False,
        "cwd": str(Path(observed["fixture"]).parent),
        "env": {
            "HOME": str(Path(observed["fixture"]).parent),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "",
            "TMPDIR": str(Path(observed["fixture"]).parent),
        },
        "shell": False,
        "stdin": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "text": True,
        "timeout": 10,
    }
    assert not Path(observed["fixture"]).exists()
    assert not Path(observed["output"]).exists()
    ready = adapter.status()
    assert ready["state"] == "ready"
    assert ready["configured"] is True
    assert ready["last_checked_at"] is not None


@pytest.mark.parametrize("unsafe_directory", [Path.cwd(), Path.home()])
def test_scan_rejects_workspace_or_home_as_temporary_root(
    adapter, monkeypatch, unsafe_directory
) -> None:
    monkeypatch.setenv("CUTLINE_OSSPREY_ENABLED", "1")
    monkeypatch.setenv("CUTLINE_OSSPREY_EXECUTABLE", "/synthetic/bin/ossprey")

    class UnsafeTemporaryDirectory:
        def __init__(self, **_kwargs) -> None:
            pass

        def __enter__(self) -> str:
            return str(unsafe_directory)

        def __exit__(self, *_args) -> None:
            return None

    def unexpected_run(*_args, **_kwargs):
        pytest.fail("unsafe scan target launched Ossprey")

    monkeypatch.setattr(
        adapter.tempfile, "TemporaryDirectory", UnsafeTemporaryDirectory
    )
    monkeypatch.setattr(subprocess, "run", unexpected_run)

    with pytest.raises(adapter.OsspreyScanError) as error:
        adapter.verify_synthetic_fixture()

    assert error.value.category == "unsafe_temporary_directory"
    assert str(error.value) == "Ossprey temporary scan location is unsafe."


@pytest.mark.parametrize(
    ("failure", "category", "message"),
    [
        (
            subprocess.TimeoutExpired("CUTLINE_CANARY_7F3A", 10),
            "timeout",
            "Ossprey scan timed out.",
        ),
        (
            OSError("CUTLINE_CANARY_7F3A"),
            "launch",
            "Ossprey scan could not start.",
        ),
    ],
)
def test_process_errors_are_fixed_bounded_and_redacted(
    adapter, monkeypatch, failure, category, message
) -> None:
    monkeypatch.setenv("CUTLINE_OSSPREY_ENABLED", "1")
    monkeypatch.setenv("CUTLINE_OSSPREY_EXECUTABLE", "/synthetic/bin/ossprey")
    observed_paths: list[Path] = []

    def fake_run(argv, **_kwargs):
        observed_paths.extend([Path(argv[2]), Path(argv[-1])])
        raise failure

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(adapter.OsspreyScanError) as error:
        adapter.verify_synthetic_fixture()

    assert error.value.category == category
    assert str(error.value) == message
    assert "CUTLINE_CANARY_7F3A" not in str(error.value)
    assert "CUTLINE_CANARY_7F3A" not in str(adapter.status())
    assert adapter.status()["state"] == "error"
    assert all(not path.exists() for path in observed_paths)


@pytest.mark.parametrize(
    ("returncode", "category", "message"),
    [
        (2, "scan_failed", "Ossprey scan failed."),
        (0, "output_missing", "Ossprey scan output is missing."),
    ],
)
def test_unsuccessful_scan_never_becomes_ready(
    adapter,
    monkeypatch,
    returncode,
    category,
    message,
) -> None:
    monkeypatch.setenv("CUTLINE_OSSPREY_ENABLED", "1")
    monkeypatch.setenv("CUTLINE_OSSPREY_EXECUTABLE", "/synthetic/bin/ossprey")

    def fake_run(argv, **_kwargs):
        return subprocess.CompletedProcess(
            argv,
            returncode,
            stdout="CUTLINE_CANARY_7F3A",
            stderr="CUTLINE_CANARY_7F3A",
        )

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(adapter.OsspreyScanError) as error:
        adapter.verify_synthetic_fixture()

    assert error.value.category == category
    assert str(error.value) == message
    assert "CUTLINE_CANARY_7F3A" not in str(adapter.status())
    assert adapter.status()["state"] == "error"


def test_scanner_result_never_changes_policy_outcomes(adapter, monkeypatch) -> None:
    monkeypatch.setenv("CUTLINE_OSSPREY_ENABLED", "1")
    monkeypatch.setenv("CUTLINE_OSSPREY_EXECUTABLE", "/synthetic/bin/ossprey")

    def fake_run(argv, **_kwargs):
        Path(argv[-1]).write_text("{}\n", encoding="utf-8")
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    policy_arguments = {
        "action_type": ActionType.EXTERNAL_WRITE,
        "data_class": DataClass.SECRET,
        "destination": "mock-collector",
        "session_allowlist": set(),
        "policy": None,
    }
    before = evaluate_external_write(**policy_arguments)

    adapter.verify_synthetic_fixture()

    after = evaluate_external_write(**policy_arguments)
    assert before == PolicyDecision.ALLOW
    assert after == before
