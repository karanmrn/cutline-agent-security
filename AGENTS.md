# CUTLINE Project Constitution

## Mission

Build one reliable, defensible, three-minute demonstration that turns a synthetic autonomous-agent incident into a replay-tested security guardrail.

## Non-negotiable safety boundary

- This repository is defensive and synthetic.
- Use only the literal canary `CUTLINE_CANARY_7F3A` or another clearly fake value.
- Never read the developer's real `.env`, shell history, keychain, SSH directory, cloud credentials, browser data, or home directory.
- Never contact an uncontrolled external endpoint.
- The `upload_artifact` tool must write only to the in-memory `MockCollector`.
- Do not add exploit payloads, persistence, credential theft, destructive actions, scanning, or real penetration-testing behaviour.
- Modal execution must use synthetic fixture data and should block network access for replay.

## Product invariant

A change is acceptable only when all of these remain true:

1. Monitor-mode incident exposes the synthetic canary to the mock collector.
2. The UI shows an evidence-linked path from untrusted instruction to secret read to external-write attempt.
3. A fixed-schema policy is generated.
4. Enforce-mode replay blocks the synthetic canary.
5. The legitimate code fix still occurs.
6. The fixture tests still pass.

## Architecture

- Backend: Python, FastAPI, Pydantic, deterministic runner, in-memory state.
- Frontend: React, TypeScript, Vite, one-screen operational console.
- Enforcement is deterministic. LLMs may explain evidence but never make the final allow/deny decision.
- Local execution is the source of truth. Sponsor adapters must degrade gracefully.

## Development workflow

Before editing:

1. Read `docs/PRD.md`, `docs/THREAT_MODEL.md`, and `docs/BUILD_PLAN.md`.
2. Inspect the relevant implementation and tests.
3. State the acceptance criteria for the current phase.
4. Keep the change limited to that phase.

After editing:

1. Run backend tests.
2. Run frontend build when frontend files changed.
3. Report exactly what passed, failed, or remains stubbed.
4. Do not claim an integration works unless it was executed successfully.

## Scope discipline

Do not introduce:

- authentication;
- multi-tenancy;
- production deployment architecture;
- a generic SOC chatbot;
- a general MCP gateway;
- a multi-agent swarm;
- real vulnerability scanning;
- a database migration framework before the local demo works;
- unnecessary framework substitutions.

## Coding conventions

- Prefer small typed functions and explicit data models.
- Preserve event IDs and evidence references through every layer.
- Redact secret values in events. The UI may display the canary status but not arbitrary payload contents.
- Return structured errors with actionable messages.
- Avoid hidden global side effects except the intentionally simple in-memory demo state.
- Add or update tests for behavioural changes.
