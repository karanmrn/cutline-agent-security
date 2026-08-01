import subprocess
import sys


def test_local_api_import_does_not_inspect_integration_credentials() -> None:
    script = """
import os

real_getenv = os.getenv
sensitive_names = {
    "OVERMIND_API_KEY",
    "SUPABASE_URL",
    "SUPABASE_SERVICE_ROLE_KEY",
}

def guarded_getenv(name, default=None):
    if name in sensitive_names:
        raise RuntimeError(f"local import inspected {name}")
    return real_getenv(name, default)

os.getenv = guarded_getenv
import app.main
"""

    completed = subprocess.run(
        [sys.executable, "-B", "-c", script],
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
