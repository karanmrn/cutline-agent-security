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

For a fresh project, apply [schema.sql](../backend/supabase/schema.sql) only. For
an existing project with legacy `cutline_*` tables, apply only
[20260801_safe_projection.sql](../backend/supabase/migrations/20260801_safe_projection.sql).
Do not replay the preserved historical provider-contract migration. Then configure:

```text
CUTLINE_SUPABASE_ENABLED=1
SUPABASE_URL=https://YOUR_PROJECT.supabase.co
SUPABASE_SECRET_KEY=sb_secret_...
```

Run full local flow. Provider becomes ready only after bulk writes to all five
tables succeed. The mirror consumes the same fixed `SafeRun` projection used by
telemetry adapters. It stores only enum-backed run status, boolean outcomes,
opaque derived run IDs, validated event lineage, tool categories, policy hashes,
and evidence event IDs. Additive `cutline_safe_*` tables isolate this contract
without rewriting or deleting legacy mirror rows. It excludes session and fixture IDs, actors, resources,
destinations, messages, raw tool names, event arguments, test output, collector
payloads, policy YAML, and regression digests. No live Supabase smoke has been
completed, so this adapter remains unverified. Local in-memory demo state
remains authoritative.

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

Ossprey is quarantined. No API, CLI command, flags, output schema, or readiness
claim is implemented because sponsor staff have not supplied an official
contract. The UI reports Ossprey as unverified and unconfigured. Add an adapter
only after receiving official documentation, a starter repository, or direct
technical support, as required by `docs/BUILD_PLAN.md`.
