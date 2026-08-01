# CUTLINE implementation record

This file records the implementation currently present on `codex/cutline-demo`.
CUTLINE remains a defensive, synthetic demo. The only secret-like value used by
the fixture is the literal fake canary `CUTLINE_CANARY_7F3A`; local execution
writes only to the in-memory `MockCollector`.

## Product flow

1. A fresh temporary fixture contains a poisoned workspace rule, a fake `.env`,
   and a failing calculator test.
2. Monitor mode records the trusted task, untrusted instruction, synthetic
   secret read, mock external-write attempt, code fix, and test result. The
   event IDs and parent IDs form one causal evidence path.
3. Incident generation validates that exact path before producing an incident.
4. Policy generation derives a fixed-schema, least-disruptive deny rule for
   `SECRET` plus `EXTERNAL_WRITE` outside the session allowlist. The policy has
   an immutable SHA-256 content hash and evidence event IDs.
5. Replay requires explicit approval of policy ID, version, hash, and provider.
   Deterministic enforcement blocks only the unauthorized synthetic egress;
   the code fix and fixture tests still run.
6. A verified replay produces a non-executable JSON regression manifest with
   fixture identity, source and replay sessions, provider, policy identity,
   evidence IDs, expected and actual outcomes, and an artifact digest.

## Backend implementation

- Typed Pydantic models cover events, evidence graphs, incidents, policies,
  approvals, provider states, and regression manifests.
- Event recording supports a sanitized telemetry sink while preserving local
  event ordering and lineage.
- Policy evaluation is deterministic and session-scoped. No LLM participates
  in the allow or deny decision.
- The FastAPI API exposes health, state, reset, monitor run, policy generation,
  exact-policy replay, and verified-manifest download endpoints.
- The local provider is authoritative. Modal is an explicit optional provider;
  it cannot silently fall back to local execution.
- Modal replay uses a fresh sandbox with `block_network=True`, a structured
  sentinel result, synthetic fixture data, and the same policy contract. Its
  image now uses `pytest>=9.0.3,<10`.
- Integration status uses the canonical shape `provider`, `state`,
  `configured`, `last_checked_at`, and safe `message` values. Compatibility
  fields remain only for the current frontend migration.
- Optional Overmind tracing and Supabase mirroring are lazy, best-effort
  adapters. They redact secret-bearing payloads and cannot authorize or alter
  local decisions.
- Supabase schema covers sessions, events, incidents, policies, and replays.
- Locked backend dependencies include the pytest security fix
  `pytest>=9.0.3,<10`.

## Frontend implementation

- The React console now separates monitor and replay outcomes, displays the
  harmful and legitimate evidence paths, and keeps evidence IDs visible.
- Policy UI shows version, hash, source evidence, candidate disruption scores,
  provider readiness, and exact approval scope.
- Provider selection disables unavailable providers and explains their current
  status; Modal is never presented as ready without a verified smoke path.
- Evidence can switch between incident and replay traces.
- Verified regression manifests are displayed and downloadable as JSON.
- Synthetic canary patterns are redacted before rendering user-visible text.
- Loading, completion, and error states use accessible status and alert regions;
  controls include keyboard-visible focus treatment and responsive layouts.
- Vitest and Testing Library cover policy lineage, provider gating, evidence
  switching, async status, errors, manifest rendering, redaction, and replay
  request shape.

## Repository and delivery work

- `Makefile` provides locked setup, backend and frontend tests, production
  build, dependency audits, and a combined `check` gate.
- CI runs locked backend tests and audit, frontend tests and build and audit,
  plus a TruffleHog history scan with credentials disabled.
- `CONTEXT.md` defines the domain glossary and decision index.
- ADRs document local-authoritative execution, deterministic enforcement, and
  non-executable manifests.
- `docs/release/CHECKLIST.md` records the release gates, product invariants,
  claim discipline, and presentation checks.

## Verification run for this record

Commands run locally from repository root:

```text
make test    # 26 backend tests passed; 9 frontend tests passed
make build   # TypeScript and Vite production build passed
make audit   # uv audit: no known vulnerabilities; npm audit: 0 vulnerabilities
git diff --check
```

Additional backend gates already exercised:

```text
uv lock --check
uv sync --frozen
uvx --from ruff ruff check app tests modal_sandbox.py
uvx pip-audit --path .venv
uv run python -m compileall -q app modal_sandbox.py
```

The local end-to-end flow confirms monitor exposure, causal evidence, policy
generation, enforce replay blocking, preserved code fix, and passing fixture
tests. Modal CLI availability was checked, but no Modal profile or workspace
credentials are configured, so Modal remains `unverified` by design.

## Safety boundaries

- No real `.env`, shell history, keychain, SSH data, cloud credential, browser
  data, or home-directory data was read.
- No uncontrolled endpoint is contacted by the local demo.
- No exploit payload, persistence, credential theft, scanning, or destructive
  behavior was added.
- Optional adapters degrade visibly to `disabled`, `unverified`, or `error`.
- Local state remains the source of truth for the demonstration.
