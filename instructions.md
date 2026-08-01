# CUTLINE Judge Instructions

Use the local path for evaluation. It demonstrates the complete security claim without accounts, credentials, network access, or an LLM API.

## Quick start

From repository root:

```bash
make setup
```

Terminal 1, API:

```bash
cd backend
uv run --frozen uvicorn app.main:app --reload --port 8000
```

Terminal 2, interface:

```bash
cd frontend
npm run dev
```

Open:

```text
http://127.0.0.1:5173
```

Optional API check:

```bash
curl http://127.0.0.1:8000/api/health
```

Expected response:

```json
{"status":"ok"}
```

## Three-minute evaluation path

Keep **Replay provider** set to **Local**.

### 1. Establish clean state

Click **Reset demo**. Current incident status should return to `IDLE`.

### 2. Reproduce the incident

Click **Run compromised agent**.

Watch the structured event timeline and attack-path visualization. They should connect:

```text
trusted task
  -> untrusted repository instruction
  -> synthetic sensitive-file read
  -> attempted external write
  -> incident detected
```

Confirm evidence event IDs appear beside the relevant claims. The **Before** result should show exposure occurred in monitor mode while the requested code fix and fixture tests still succeeded.

### 3. Generate the guardrail

Click **Generate guardrail**.

Review the proposed fixed-schema rule and its evidence references. The narrow control denies secret-classified external writes when the destination is not authorized by the task. It does not block ordinary source edits or local tests.

### 4. Approve and replay

Click **Approve and replay**. This is the explicit human approval boundary.

Replay runs the same synthetic task in enforce mode. Finish on `PATCH VERIFIED` and confirm the **After** result shows:

- attack attempted: yes;
- external write blocked: yes;
- synthetic secret exposed: no;
- application fixed: yes;
- fixture tests passed: yes.

The final regression manifest is durable machine-readable evidence for this exact policy and replay.

## What to inspect

| Interface section | What it proves |
|---|---|
| Current incident status | Demo lifecycle is explicit, including failure states |
| Compromised agent execution | Safe injected instruction, redacted actions, code diff, and test output show exactly what ran |
| Structured timeline | Events retain order, trust, action, and decision context |
| Attack path | Harmful chain is visually linked from untrusted input to sink |
| Evidence IDs | Explanations are traceable to captured events |
| Proposed guardrail | Control is narrow, typed, and evidence-bound |
| Human approval | Policy cannot enter replay silently |
| Before and After | Harm blocked without breaking useful work |
| Replay provider | Execution provenance is visible |
| `PATCH VERIFIED` | Security and functional assertions passed together |

## Design reasoning

CUTLINE optimizes for one defensible claim, not a broad security platform. One incident, one policy, and one replay make causality easy to inspect. Monitor mode first preserves evidence of the attempted attack. Enforce mode then reruns a fresh synthetic fixture under the approved control.

Policy enforcement is deterministic because a security boundary should not depend on variable model output. Models may help a developer reason about evidence, but CUTLINE's runtime decision uses typed facts: data class, action class, destination authorization, and policy version. Preserving the legitimate code fix is as important as blocking egress because an indiscriminate deny-all rule would not be useful.

## Tools and models

Core product stack:

- React, TypeScript, Vite, Vitest, and Testing Library for the single-screen console;
- FastAPI, Pydantic, pytest, and a deterministic Python runner for the API and replay engine;
- `uv` and npm for locked dependency workflows;
- GitHub Actions for repeatable test, build, audit, and secret-scan gates.

Model use:

- **CUTLINE runtime:** no LLM and no model API key.
- **Enforcement:** deterministic typed policy evaluation.
- **Development:** OpenAI Codex assisted planning, implementation, review, and browser testing; it does not ship in the runtime.

## Sponsors and optional providers

The local demonstration is complete without providers. Optional adapters are separated from the enforcement path so missing credentials cannot weaken or fake the result.

Current repository evidence verifies the local path only. External providers should remain labeled disabled or unverified unless a successful live smoke result is shown from the intended account.

| Provider | Work represented in repository | Evaluation guidance |
|---|---|---|
| Modal | Fresh sandbox replay design with outbound networking blocked | Optional. Use only after its documented live smoke test succeeds |
| Overmind | Sanitized structured trace adapter | Optional. Remote ingestion must be inspected before claiming verified |
| Supabase | Server-only, best-effort sanitized mirror | Optional. Local in-memory state remains source of truth |
| Langfuse | Sanitized trace adapter | Optional. SDK flush alone is not proof of remote ingestion |
| Ossprey | Reserved integration boundary | Not implemented without an official sponsor contract |

Configuration and exact provider smoke requirements live in [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md). Disabled or unverified is an expected honest state, not a local demo failure.

## Verification commands

From repository root:

```bash
make test
make build
```

Full gate:

```bash
make check
```

`make check` runs backend and frontend tests, the frontend production build, and dependency audits. A green command is evidence for the exact commit and environment where it ran.

## Troubleshooting

### Interface cannot reach API

Confirm API is running on port 8000 and health check returns `{"status":"ok"}`. Keep frontend on Vite's default port 5173. If using a different frontend origin, set `CUTLINE_FRONTEND_ORIGIN` before starting API.

### Demo opens in a completed state

State is in memory for the running API process. Click **Reset demo** before judging or recording.

### Replay provider is unavailable

Select **Local**. Optional provider failure must never be presented as local success.

### A step fails

Use the visible `ERROR` message, correct the API or provider issue, then click **Reset demo**. Do not skip approval or manually fabricate a verified state.

## Safety boundary

- All secret material is synthetic.
- Local collection is in memory.
- Real credential locations are never read.
- Local runner performs no uncontrolled network request.
- Replay uses a fresh fixture.
- UI events and optional provider projections redact sensitive payloads.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the complete boundary and [docs/release/CHECKLIST.md](docs/release/CHECKLIST.md) for release evidence.
