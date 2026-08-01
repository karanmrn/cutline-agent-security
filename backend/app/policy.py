from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable

import yaml

from app.incident import find_attack_chain
from app.models import (
    ActionType,
    DataClass,
    DestinationMatch,
    Event,
    PolicyCandidate,
    PolicyDecision,
    PolicyEffect,
    PolicyMatch,
    ProposedPolicy,
)


def evaluate_external_write(
    *,
    action_type: ActionType,
    data_class: DataClass,
    destination: str,
    session_allowlist: set[str],
    policy: ProposedPolicy | None,
) -> PolicyDecision:
    if policy is None:
        return PolicyDecision.ALLOW

    destination_matches = (
        policy.match.destination == DestinationMatch.NOT_IN_SESSION_ALLOWLIST
        and destination not in session_allowlist
    )
    prohibited = (
        data_class == policy.match.data_class
        and action_type == policy.match.action_type
        and destination_matches
    )
    if prohibited and policy.effect == PolicyEffect.DENY:
        return PolicyDecision.DENY
    return PolicyDecision.ALLOW


def build_policy(events: Iterable[Event]) -> ProposedPolicy:
    events = list(events)
    untrusted_instruction, secret_read, external_write = find_attack_chain(events)

    policy_document = {
        "id": "block-secret-egress",
        "version": 1,
        "match": {
            "data_class": "SECRET",
            "action_type": "EXTERNAL_WRITE",
            "destination": "NOT_IN_SESSION_ALLOWLIST",
        },
        "effect": "DENY",
        "evidence": {
            "event_ids": [
                untrusted_instruction.event_id,
                secret_read.event_id,
                external_write.event_id,
            ]
        },
    }

    candidates = [
        PolicyCandidate(
            id="disable-agent",
            title="Disable the agent",
            effect="DENY_ALL",
            disruption_score=100,
        ),
        PolicyCandidate(
            id="block-network",
            title="Block every outbound action",
            effect="DENY_ALL_EXTERNAL_WRITE",
            disruption_score=20,
        ),
        PolicyCandidate(
            id="approve-uploads",
            title="Require approval for every upload",
            effect="REQUIRE_APPROVAL",
            disruption_score=8,
        ),
        PolicyCandidate(
            id="block-secret-egress",
            title="Deny secret egress to unauthorized destinations",
            effect="DENY",
            disruption_score=1,
            selected=True,
        ),
    ]

    return ProposedPolicy(
        id="block-secret-egress",
        policy_hash=hashlib.sha256(
            json.dumps(
                policy_document,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest(),
        title="Block unauthorized secret egress",
        description=(
            "Deny SECRET-classified external writes when the destination is not "
            "authorized by the user's task."
        ),
        effect=PolicyEffect.DENY,
        match=PolicyMatch(
            data_class=DataClass.SECRET,
            action_type=ActionType.EXTERNAL_WRITE,
            destination=DestinationMatch.NOT_IN_SESSION_ALLOWLIST,
        ),
        disruption_score=1,
        evidence_event_ids=policy_document["evidence"]["event_ids"],
        candidates=candidates,
        yaml=yaml.safe_dump(policy_document, sort_keys=False),
    )
