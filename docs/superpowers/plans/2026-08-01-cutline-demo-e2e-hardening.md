# CUTLINE Demo E2E Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make CUTLINE's single-screen demo communicate the full incident-to-verified-patch story within five seconds and prove it through local end-to-end browser testing.

**Architecture:** Preserve FastAPI runner, policy, replay, and in-memory state semantics. Derive a frontend-only lifecycle state from existing API data and in-flight actions, surface it as the dominant console status, and keep evidence, approval, provider selection, and before/after proof on one page. Use existing Vitest seams for state transitions, then validate the real FastAPI and Vite stack through Chrome Computer Use.

**Tech Stack:** React, TypeScript, Vite, Vitest, FastAPI, Pydantic, pytest, Chrome Computer Use.

## Global Constraints

- One page only, with no authentication, navigation sidebar, settings page, or extra scenarios.
- Preserve backend semantics and do not implement sponsor integrations.
- Never display the raw synthetic secret.
- Keep local execution authoritative and deterministic.
- Preserve evidence event IDs from incident through policy and replay.

---

### Task 1: Baseline and lifecycle contract

**Files:**
- Modify: `frontend/src/App.test.tsx`
- Inspect: `frontend/src/App.tsx`
- Inspect: `backend/app/main.py`

**Interfaces:**
- Consumes: `DemoState`, existing API actions, and in-flight action names.
- Produces: executable assertions for `IDLE`, `RUNNING`, `INCIDENT DETECTED`, `GUARDRAIL PROPOSED`, `AWAITING APPROVAL`, `REPLAYING`, `PATCH VERIFIED`, and `ERROR`.

- [x] Run backend tests and frontend tests unchanged to establish baseline.
- [x] Launch FastAPI and Vite, reset the demo, and capture current Chrome state.
- [x] Add a focused UI test that expects the explicit lifecycle state sequence and required security-story labels.
- [x] Run the focused test and confirm it fails because the current incident status is absent or incomplete.

### Task 2: Single-screen status and story hierarchy

**Files:**
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/styles.css`
- Test: `frontend/src/App.test.tsx`

**Interfaces:**
- Consumes: `DemoState`, `ActionName`, and redacted run/policy data.
- Produces: a typed derived lifecycle status and a prominent current-status/story strip.

- [x] Implement the smallest typed lifecycle derivation needed to satisfy the failing test.
- [x] Render current status and the nine story steps without exposing secret contents.
- [x] Keep actions gated in the existing order and make human approval explicit.
- [x] Keep before/after cards, attack path, event IDs, provider label, and final `PATCH VERIFIED` visually dominant.
- [x] Run focused frontend tests until green, then run the full frontend suite.

### Task 3: Real end-to-end demo verification

**Files:**
- No production changes unless a reproduced defect requires a regression test first.

**Interfaces:**
- Consumes: local FastAPI at `http://localhost:8000` and Vite at `http://localhost:5173`.
- Produces: verified browser evidence for reset, compromised run, guardrail generation, approval, replay, error recovery, responsive layout, and secret redaction.

- [x] Use Chrome Computer Use to reset and execute all three demo actions in sequence.
- [x] Inspect each state for required sections, evidence IDs, provider truthfulness, and final proof.
- [x] Verify browser does not show `CUTLINE_CANARY_7F3A`.
- [x] Exercise one API error path and confirm `ERROR` appears with actionable copy, then reset.
- [x] Inspect desktop and narrow viewport layout for overflow or inaccessible controls.

### Task 4: Final verification and review

**Files:**
- Review all files changed during this task while preserving unrelated dirty changes.

**Interfaces:**
- Consumes: final worktree and user acceptance checklist.
- Produces: exact command results and changed-file report.

- [x] Run `cd backend && uv run --frozen pytest -q`.
- [x] Run `cd frontend && npm test`.
- [x] Run `cd frontend && npm run build`.
- [x] Review diff for scope, accessibility, canary redaction, and backend semantic preservation.
- [x] Dispatch an independent verifier subagent and resolve any failing verdict.
- [x] Report exact passes, failures, remaining stubs, and files changed by this task.
