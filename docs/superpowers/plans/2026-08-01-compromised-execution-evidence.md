# Compromised Execution Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use test-driven development for every behavior change. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the compromised agent's trusted task, injected repository instruction, redacted tool activity, code correction, and test result visible on the existing CUTLINE screen without exposing synthetic secret contents.

**Architecture:** Extend `RunResult` with a typed, secret-free execution-evidence projection produced by the deterministic runner. Render that projection and existing redacted event fields in one compact frontend panel, while keeping incident and replay traces distinguishable. Enforcement, policy, provider, and integration behavior remain unchanged.

**Tech Stack:** Python, FastAPI, Pydantic, pytest, React, TypeScript, Vitest, Testing Library, Vite.

## Global Constraints

- One page only. No navigation, authentication, settings, or extra scenario.
- Never return or render the raw synthetic secret.
- Preserve monitor, policy, replay, regression-manifest, and provider semantics.
- Do not modify sponsor integrations.
- Do not commit or push during repository-wide review.

---

### Task 1: Typed safe execution evidence

**Files:**
- Modify: `backend/app/models.py`
- Modify: `backend/app/runner.py`
- Test: `backend/tests/test_runner.py`

**Interfaces:**
- Produces: optional `RunResult.execution_evidence` containing trusted task, injected instruction, instruction path, code path, code before, code after, test command, and attempted destination.
- Safety: serialized `RunResult`, events, and execution evidence must not contain the synthetic canary.

- [ ] Write a failing runner test asserting exact safe evidence and canary absence.
- [ ] Run `cd backend && uv run --frozen pytest -q tests/test_runner.py` and confirm expected failure because `execution_evidence` is absent.
- [ ] Add typed Pydantic evidence model and populate it from the deterministic synthetic fixture constants.
- [ ] Re-run focused runner tests and confirm pass.

### Task 2: Compromised agent execution panel

**Files:**
- Modify: `frontend/src/types.ts`
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/styles.css`
- Test: `frontend/src/App.test.tsx`

**Interfaces:**
- Consumes: `RunResult.execution_evidence` from Task 1 and existing `Event.arguments_redacted`, `resource`, `destination`, and `test_output`.
- Produces: accessible `Compromised agent execution` region with trusted task, prompt injection, redacted action log, code diff, and test result.

- [ ] Write failing component tests asserting safe prompt, code before/after, destination, redacted payload, and test output are visible for incident evidence.
- [ ] Add a failing test proving replay completion does not hide the compromised execution narrative.
- [ ] Run `cd frontend && npm test -- --run src/App.test.tsx` and confirm expected failures because panel is absent.
- [ ] Add typed frontend contract and compact panel using existing redaction helper for every dynamic string.
- [ ] Ensure event details display resource, destination, and redacted arguments without raw secret data.
- [ ] Keep existing lifecycle headings, human approval control, provider truth, before/after cards, graph, manifest, and integration panel unchanged.
- [ ] Make `GUARDRAIL PROPOSED` the primary post-generation lifecycle heading and label the approval control `AWAITING APPROVAL`.
- [ ] Hide completed replay selection controls or synchronize them with the persisted replay provider; redact every provider label.
- [ ] Align frontend `RunResult.fixture_id` and `DemoState.incident` with the public backend response.
- [ ] Render harmful and legitimate causal labels from `graph.edges` instead of unlabeled position-only arrows.
- [ ] Re-run focused frontend tests and confirm pass.

### Task 3: End-to-end verification

**Files:**
- No production edits unless a newly reproduced blocker requires a minimal TDD fix.

- [ ] Run backend tests.
- [ ] Run frontend tests and production build.
- [ ] Drive real browser from `IDLE` through `PATCH VERIFIED` using Local replay.
- [ ] Confirm compromised panel remains visible after replay and shows prompt injection, code diff, redacted upload, and passing test output.
- [ ] Search DOM for raw synthetic canary and require zero matches.
- [ ] Check browser console for errors.
- [ ] Check 1440 by 900 and 390 by 844 for horizontal overflow.
- [ ] Report exact commands, results, changed files, and any remaining limitation.
