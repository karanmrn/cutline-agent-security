# CUTLINE Provider Integrations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add safe, opt-in Langfuse, Overmind, Supabase, and Modal integration paths while keeping the fully local CUTLINE flow authoritative and unchanged. Ossprey remains quarantined pending an official contract.

**Architecture:** Provider adapters consume a fixed sanitized projection of completed synthetic runs. Telemetry and persistence are best-effort side effects after deterministic execution, never inputs to policy evaluation. Modal is the sole alternate execution provider and remains network-blocked. No Ossprey command contract is assumed.

**Tech Stack:** Python 3.11+, FastAPI, Pydantic, Langfuse 4.14.2, Overmind 0.1.57, Supabase Python 2.31.0, Modal 1.5.3, pytest 9, React/Vite status UI.

## Global Constraints

- Never read the developer's real `.env`, shell history, keychain, SSH directory, cloud credentials, browser data, or home directory.
- Use only the synthetic canary `CUTLINE_CANARY_7F3A`; never send its literal value to telemetry or persistence.
- Never send event messages, arguments, payloads, file contents, paths, test output, policy YAML, credentials, user IDs, session IDs, or fixture IDs to telemetry.
- Local in-memory state remains authoritative. Provider failures are visible status only and cannot change run, policy, approval, or replay outcomes.
- Deterministic application code remains the only enforcement authority.
- Modal replay uses fresh synthetic fixtures and `block_network=True`; no credentials or telemetry SDKs enter its sandbox.
- Supabase credentials remain server-only. No browser client, publishable key, Realtime dependency, or authentication feature is added.
- Ossprey stays unconfigured and unverified until sponsor staff provide an official API, CLI, starter repository, or direct technical support.
- Every production change follows red-green TDD. No live credential appears in tests, fixtures, commands committed to git, logs, UI, or documentation.

---

### Task 1: Shared sanitized provider projection

**Files:**
- Create: `backend/app/integrations/safe_projection.py`
- Modify: `backend/app/runner.py`
- Test: `backend/tests/test_integrations.py`
- Test: `backend/tests/test_runner.py`

**Interfaces:**
- Produces: `SafeEvent`, `SafeRun`, `project_event(event: Event) -> SafeEvent`, and `project_run(run: RunResult) -> SafeRun`.
- Produces: `emit_run_telemetry(run: RunResult) -> None`, implemented as a no-throw fan-out after `RunResult` construction.

- [ ] **Step 1: Write failing projection tests**

  Construct an `Event` with canary and credential-like values in every free-text field. Assert serialized projection contains only validated event IDs, parent IDs, enum values, sequence number, normalized tool category, and normalized outcome. Assert every forbidden value is absent.

- [ ] **Step 2: Verify RED**

  Run `cd backend && uv run pytest -q tests/test_integrations.py tests/test_runner.py`. Expected failure: projection and post-run fan-out do not exist.

- [ ] **Step 3: Implement fixed Pydantic projection**

  Use `ConfigDict(extra="forbid")`, enum-backed fields, `evt_[0-9a-f]{8}` validation, and fixed mappings for known tool names and outcomes. Unknown free text maps to `unknown`; no arbitrary string passes through.

- [ ] **Step 4: Add no-throw post-run fan-out**

  Build `RunResult` first, then call telemetry adapters inside independent `try/except Exception` blocks. Return the already-built result unchanged even when every adapter fails.

- [ ] **Step 5: Verify GREEN**

  Run focused tests and compare all monitor/enforce invariants with disabled and deliberately failing telemetry.

### Task 2: Langfuse v4 tracing

**Files:**
- Create: `backend/app/integrations/langfuse_trace.py`
- Modify: `backend/app/integrations/safe_projection.py`
- Modify: `backend/app/state.py`
- Modify: `backend/pyproject.toml`
- Modify: `backend/uv.lock`
- Modify: `backend/.env.example`
- Test: `backend/tests/test_langfuse.py`

**Interfaces:**
- Produces: `trace_run(run: SafeRun) -> None` and `status() -> IntegrationStatus-compatible dict`.
- Consumes only `SafeRun`; never imports or accepts raw `Event` or `RunResult`.

- [ ] **Step 1: Write failing Langfuse tests**

  Verify disabled and missing-key states, lazy import, one `cutline-run` root, one `fix-and-verify` child, six nested event observations, no input/output capture, flush after completion, and no-throw behavior for initialization, observation, close, and flush failures.

- [ ] **Step 2: Verify RED**

  Run `cd backend && uv run pytest -q tests/test_langfuse.py`. Expected failure: module and dependency are absent.

- [ ] **Step 3: Implement official Python v4 client path**

  Pin `langfuse==4.14.2`. Enable only with `CUTLINE_LANGFUSE_ENABLED=1` plus public key, secret key, and base URL. Lazy-import `get_client`, use observation context managers with fixed names/types, attach only `SafeRun` fields, and call `flush()` after each completed run.

- [ ] **Step 4: Report truthful status**

  `disabled` without flag, `error` with missing configuration or SDK failure, and `unverified` after client creation or SDK flush. Report `ready` only after provider-side ingestion is confirmed. Errors are bounded fixed-category messages with no provider exception text.

- [ ] **Step 5: Verify GREEN**

  Run Langfuse tests, full backend suite, Ruff, compile, and secret scan.

### Task 3: Overmind structured tracing

**Files:**
- Modify: `backend/app/integrations/overmind_trace.py`
- Modify: `backend/app/integrations/safe_projection.py`
- Modify: `backend/app/state.py`
- Modify: `backend/pyproject.toml`
- Modify: `backend/uv.lock`
- Modify: `backend/.env.example`
- Test: `backend/tests/test_overmind.py`

**Interfaces:**
- Produces: `trace_run(run: SafeRun) -> None` and canonical `status()`.
- Consumes only `SafeRun`.

- [ ] **Step 1: Write failing Overmind tests**

  Verify flag plus API key requirement, `providers=None`, stable service and agent identity, one entry-point/workflow/event tree, no captured inputs/outputs, flush, allowlisted attributes, and failure isolation.

- [ ] **Step 2: Verify RED**

  Run `cd backend && uv run pytest -q tests/test_overmind.py`. Expected failure: current adapter emits disconnected raw-event spans.

- [ ] **Step 3: Implement structured adapter**

  Pin `overmind==0.1.57`. Remove event callback integration. Use fixed span names and safe projected attributes only. Never attach session, fixture, user, payload, exception, message, path, or credential data.

- [ ] **Step 4: Report truthful status and verify GREEN**

  Keep `unverified` until a trace flush succeeds, record bounded error categories, then run focused and full backend tests.

### Task 4: Supabase server-only mirror

**Files:**
- Modify: `backend/app/integrations/supabase_store.py`
- Modify: `backend/supabase/schema.sql`
- Preserve: `backend/supabase/migrations/20260801_provider_contract.sql`
- Create: `backend/supabase/migrations/20260801_safe_projection.sql`
- Modify: `backend/app/main.py`
- Modify: `backend/app/state.py`
- Modify: `backend/pyproject.toml`
- Modify: `backend/uv.lock`
- Modify: `backend/.env.example`
- Test: `backend/tests/test_supabase.py`
- Test: `backend/tests/test_api.py`

**Interfaces:**
- Consumes sanitized persistence rows only.
- Requires `CUTLINE_SUPABASE_ENABLED=1`, `SUPABASE_URL`, and `SUPABASE_SECRET_KEY`.

- [ ] **Step 1: Write failing schema, sanitization, and state tests**

  Assert row keys exactly match SQL columns, every string is canary-free, raw arguments/test output/payloads are absent, client creation stays `unverified`, successful five-table bulk writes become `ready`, failure becomes timestamped `error`, and retry clears prior error.

- [ ] **Step 2: Verify RED**

  Run `cd backend && uv run pytest -q tests/test_supabase.py tests/test_api.py`. Expected failures: missing fixed-schema safe tables, unsafe projection fields, per-row writes, and premature readiness.

- [ ] **Step 3: Implement corrected mirror and migration**

  Pin `supabase==2.31.0`. Bulk-upsert sanitized rows in dependency order to additive `cutline_safe_*` tables. Preserve published migrations and legacy tables, enable RLS on every safe table, revoke browser roles, and add no browser policies. Local replay returns successfully even when mirror fails.

- [ ] **Step 4: Verify GREEN**

  Run focused tests, full backend tests, schema contract check, Ruff, compile, and dependency audit.

### Task 5: Modal live-smoke hardening

**Files:**
- Modify: `backend/modal_sandbox.py`
- Modify: `backend/app/providers.py`
- Modify: `backend/pyproject.toml`
- Modify: `backend/uv.lock`
- Create: `backend/tests/test_modal_sandbox.py`
- Test: `backend/tests/test_api.py`

**Interfaces:**
- `run_in_modal(mode: RunMode, *, policy: ProposedPolicy | None) -> RunResult` returns only a verified Modal result.

- [ ] **Step 1: Write failing Modal contract tests**

  Fake only Modal client boundary. Assert exact app lookup, `block_network=True`, timeouts, no secrets/volumes/tunnels/OIDC, exact policy JSON, one sentinel, invariant validation, bounded redacted errors, `terminate(wait=True)`, and `detach()` on every path.

- [ ] **Step 2: Verify RED**

  Run `cd backend && uv run --extra modal pytest -q tests/test_modal_sandbox.py tests/test_api.py`. Expected failures: raw errors, missing invariant validation, and incomplete cleanup.

- [ ] **Step 3: Implement hardened smoke**

  Pin `modal==1.5.3` and remote image dependencies to lock-resolved versions. Exit successfully only for Modal enforce result with attempted-and-blocked egress, no exposure, empty collector, code fixed, and tests passed.

- [ ] **Step 4: Verify GREEN**

  Run focused tests with Modal extra, full backend suite, and local worker contract without any live RPC.

### Task 6: Ossprey quarantine

**Files:**
- Modify: `backend/app/state.py`
- Test: `backend/tests/test_integrations.py`

**Interfaces:**
- Produces only a canonical unverified, unconfigured integration status.
- Consumes no environment variables and invokes no process or network boundary.

- [x] **Step 1: Reject undocumented contracts**

  Keep Ossprey unconfigured and unverified until sponsor staff provide an official API, CLI, starter repository, or direct technical support.

- [x] **Step 2: Preserve local authority**

  Confirm Ossprey cannot participate in policy evaluation or alter local demo results.

### Task 7: Documentation, full verification, and live smoke gates

**Files:**
- Modify: `README.md`
- Modify: `docs/DEMO_SCRIPT.md`
- Modify: `docs/release/CHECKLIST.md`
- Modify: `.github/workflows/ci.yml`

**Interfaces:**
- Documents environment-only configuration and truthful provider state transitions.

- [ ] **Step 1: Update locked CI and operator documentation**

  CI installs all optional SDK extras for mocked contract tests but supplies no credentials and makes no provider calls. Documentation names exact success assertions, teardown, and missing-credential behavior.

- [ ] **Step 2: Run full local verification**

  Run `make check`, backend tests with all extras, frontend production build, Ruff, compile, dependency audits, `git diff --check`, and repository secret scan.

- [ ] **Step 3: Run authorized live smokes only with secure environment injection**

  Run Modal, Langfuse, Overmind, and Supabase separately. Send only synthetic sanitized data. Record provider trace or row identifiers, status transitions, and teardown result without recording credentials. Keep Ossprey quarantined.

- [ ] **Step 4: Independent review and commit**

  Review every provider against global constraints, rerun any affected gate, commit normal code, and push `codex/cutline-demo` only after local gates pass. Report live providers as verified only when observed successfully.
