# Optional Provider Integrations

CUTLINE runs fully without external providers. Optional adapters consume only
synthetic, sanitized output after deterministic execution has completed. They
cannot authorize an action, change a policy decision, or convert provider
failure into local success.

Keep all credentials in process environment or official provider profiles.
Never place them in repository files, frontend code, traces, screenshots, or
shell commands committed to git.

## Langfuse

Langfuse receives one trace per completed local run. Trace input, output,
metadata, user identity, session identity, file paths, event messages, and
payloads are omitted. A successful SDK flush means delivery was queued; inspect
Langfuse before claiming ingestion is verified.

Required environment:

```text
CUTLINE_LANGFUSE_ENABLED=1
LANGFUSE_PUBLIC_KEY=...
LANGFUSE_SECRET_KEY=...
LANGFUSE_BASE_URL=https://cloud.langfuse.com
```

Run monitor and replay locally, then confirm two `cutline-run` traces with the
fixed nested event structure and no synthetic canary.

## Overmind

Overmind receives the same safe projection through its native SDK. Provider
auto-instrumentation is disabled, so unrelated libraries cannot expand capture
scope.

Required environment:

```text
CUTLINE_OVERMIND_ENABLED=1
OVERMIND_API_KEY=...
OVERMIND_AGENT_ID=...
OVERMIND_PROJECT_ID=...
```

After local monitor and replay runs, confirm one `cutline.run` entry point per
run, each with one workflow and fixed child event spans. SDK flush success is
not proof that console ingestion completed.

## Supabase

Supabase is a server-only, best-effort mirror. Local memory remains source of
truth. No publishable key, browser client, authentication, or Realtime
dependency is used.

Apply [schema.sql](../backend/supabase/schema.sql) and the matching migration in
[migrations](../backend/supabase/migrations), then configure:

```text
CUTLINE_SUPABASE_ENABLED=1
SUPABASE_URL=https://YOUR_PROJECT.supabase.co
SUPABASE_SECRET_KEY=sb_secret_...
```

Run full local flow. Provider becomes ready only after bulk writes to all five
tables succeed. Verify stored strings contain no raw synthetic canary and no
event arguments, test output, or collector payload.

## Modal

Modal executes only enforce replay in a fresh Sandbox. Outbound networking is
blocked and no host credentials, environment file, volume, tunnel, or identity
token enters Sandbox.

```bash
cd backend
uv sync --frozen --extra modal
uv run modal setup --profile cutline-demo
MODAL_PROFILE=cutline-demo CUTLINE_MODAL_ENABLED=1 \
  uv run --frozen python modal_sandbox.py --mode enforce
```

Success requires a Modal enforce result with attempted and blocked egress, no
exposure, empty collector, successful code fix, and passing fixture tests.
Sandbox termination waits for completion and always detaches.

## Ossprey

Ossprey verification is local-only. CUTLINE requires an explicit absolute CLI
path and scans a disposable generated fixture using documented safe dry-run
mode. It never scans the repository, workspace, or home directory and never
affects enforcement.

```text
CUTLINE_OSSPREY_ENABLED=1
CUTLINE_OSSPREY_EXECUTABLE=/absolute/path/to/ossprey
```

```bash
cd backend
uv run python -c \
  'from app.integrations.ossprey_scan import verify_synthetic_fixture; verify_synthetic_fixture()'
```

This separate-process smoke proves only the local CLI adapter contract. Its
status is process-local, so the running FastAPI UI remains unverified. Do not
claim UI readiness and do not enable this adapter until an official Ossprey CLI
binary is installed.
