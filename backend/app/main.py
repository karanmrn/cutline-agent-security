from __future__ import annotations

import os

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.models import DemoState, ReplayApproval, RunMode
from app.policy import build_policy
from app.runner import AgentRunner
from app.state import store

app = FastAPI(
    title="CUTLINE API",
    version="0.1.0",
    description="Synthetic defensive agent incident replay demo",
)

frontend_origin = os.getenv("CUTLINE_FRONTEND_ORIGIN", "http://localhost:5173")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[frontend_origin],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/state", response_model=DemoState)
def get_state() -> DemoState:
    return store.snapshot()


@app.post("/api/demo/reset", response_model=DemoState)
def reset_demo() -> DemoState:
    return store.reset()


@app.post("/api/demo/run-vulnerable", response_model=DemoState)
def run_vulnerable() -> DemoState:
    run = AgentRunner(provider="local").run(RunMode.MONITOR)
    store.set_vulnerable(run)
    return store.snapshot()


@app.post("/api/demo/generate-policy", response_model=DemoState)
def generate_policy() -> DemoState:
    state = store.snapshot()
    if not state.vulnerable_run:
        raise HTTPException(
            status_code=409,
            detail="Run the compromised agent before generating a guardrail.",
        )
    try:
        policy = build_policy(state.vulnerable_run.events)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    store.set_policy(policy)
    return store.snapshot()


@app.post("/api/demo/replay", response_model=DemoState)
def replay(approval: ReplayApproval) -> DemoState:
    state = store.snapshot()
    if not state.proposed_policy:
        raise HTTPException(
            status_code=409,
            detail="Generate and approve a guardrail before replay.",
        )
    if (
        approval.policy_id != state.proposed_policy.id
        or approval.policy_version != state.proposed_policy.version
    ):
        raise HTTPException(
            status_code=409,
            detail="Approve the currently proposed guardrail before replay.",
        )
    run = AgentRunner(provider="local").run(
        RunMode.ENFORCE,
        policy=state.proposed_policy,
    )
    store.set_replay(run)
    return store.snapshot()
