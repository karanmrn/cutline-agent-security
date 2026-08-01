from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class TrustLevel(StrEnum):
    TRUSTED = "TRUSTED"
    INTERNAL = "INTERNAL"
    UNTRUSTED = "UNTRUSTED"


class DataClass(StrEnum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    SECRET = "SECRET"


class ActionType(StrEnum):
    READ = "READ"
    WRITE = "WRITE"
    EXECUTE = "EXECUTE"
    EXTERNAL_WRITE = "EXTERNAL_WRITE"
    DELETE = "DELETE"
    CREDENTIAL_USE = "CREDENTIAL_USE"


class PolicyDecision(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    NOT_EVALUATED = "NOT_EVALUATED"


class RunMode(StrEnum):
    MONITOR = "monitor"
    ENFORCE = "enforce"


class PolicyEffect(StrEnum):
    DENY = "DENY"


class DestinationMatch(StrEnum):
    NOT_IN_SESSION_ALLOWLIST = "NOT_IN_SESSION_ALLOWLIST"


class Event(BaseModel):
    event_id: str
    session_id: str
    parent_event_id: str | None = None
    sequence_number: int
    actor: str
    source_type: str
    source_trust: TrustLevel
    data_class: DataClass
    tool_name: str
    resource: str | None = None
    destination: str | None = None
    action_type: ActionType
    arguments_redacted: dict[str, Any] = Field(default_factory=dict)
    policy_decision: PolicyDecision = PolicyDecision.NOT_EVALUATED
    outcome: str
    message: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class GraphNode(BaseModel):
    id: str
    label: str
    kind: str
    status: str
    event_id: str | None = None


class GraphEdge(BaseModel):
    source: str
    target: str
    label: str
    status: str


class EvidenceGraph(BaseModel):
    nodes: list[GraphNode]
    edges: list[GraphEdge]


class RunResult(BaseModel):
    session_id: str
    mode: RunMode
    provider: str = "local"
    status: str
    secret_exposed: bool
    exfiltration_attempted: bool
    exfiltration_blocked: bool
    code_fixed: bool
    tests_passed: bool
    test_output: str
    collector_count: int
    events: list[Event]
    graph: EvidenceGraph


class PolicyCandidate(BaseModel):
    id: str
    title: str
    effect: str
    disruption_score: int
    selected: bool = False


class PolicyMatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    data_class: DataClass
    action_type: ActionType
    destination: DestinationMatch


class ProposedPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    version: int = 1
    title: str
    description: str
    effect: PolicyEffect
    match: PolicyMatch
    disruption_score: int
    evidence_event_ids: list[str]
    candidates: list[PolicyCandidate]
    yaml: str


class ReplayApproval(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approved: Literal[True]
    policy_id: str
    policy_version: int


class DemoState(BaseModel):
    vulnerable_run: RunResult | None = None
    proposed_policy: ProposedPolicy | None = None
    replay_run: RunResult | None = None
    integrations: dict[str, dict[str, Any]] = Field(default_factory=dict)
