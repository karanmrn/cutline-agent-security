from __future__ import annotations

import os

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.incident import build_incident
from app.integrations.supabase_store import mirror as supabase_mirror
from app.models import (
    DemoState,
    IntegrationStatus,
    RegressionManifest,
    ReplayApproval,
    RunMode,
)
from app.policy import build_policy
from app.providers import ProviderUnavailable, get_replay_provider
from app.regression import build_regression_manifest
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


@app.get("/api/demo/regression-manifest", response_model=RegressionManifest)
def get_regression_manifest() -> RegressionManifest:
    manifest = store.snapshot().regression_manifest
    if not manifest:
        raise HTTPException(
            status_code=409,
            detail="Complete a verified replay before downloading the regression manifest.",
        )
    return manifest


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
        incident = build_incident(state.vulnerable_run.events)
        policy = build_policy(state.vulnerable_run.events)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    store.set_policy(policy)
    store.set_incident(incident)
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
        or approval.policy_hash != state.proposed_policy.policy_hash
    ):
        raise HTTPException(
            status_code=409,
            detail="Approve the currently proposed guardrail before replay.",
        )
    try:
        run = get_replay_provider(approval.provider).replay(state.proposed_policy)
    except ProviderUnavailable as exc:
        store.set_integration_error(
            approval.provider.value,
            str(exc),
            configured=os.getenv("CUTLINE_MODAL_ENABLED") == "1",
        )
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    manifest = build_regression_manifest(
        vulnerable_run=state.vulnerable_run,
        replay_run=run,
        policy=state.proposed_policy,
    )
    store.set_replay(run, manifest)
    store.set_integration_ready(approval.provider.value)
    supabase_mirror.persist(
        state.vulnerable_run,
        run,
        state.proposed_policy,
    )
    supabase_status = supabase_mirror.status()
    if supabase_status["state"] != "disabled":
        store.set_integration_status(IntegrationStatus.model_validate(supabase_status))
    return store.snapshot()
