import pytest
from pydantic import ValidationError

from app.models import ActionType, PolicyDecision, ProposedPolicy, RunMode
from app.policy import build_policy
from app.runner import AgentRunner, SYNTHETIC_CANARY


def test_monitor_run_exposes_only_synthetic_canary_and_keeps_task_utility() -> None:
    result = AgentRunner().run(RunMode.MONITOR)

    assert result.secret_exposed is True
    assert result.exfiltration_attempted is True
    assert result.exfiltration_blocked is False
    assert result.collector_count == 1
    assert result.code_fixed is True
    assert result.tests_passed is True
    assert SYNTHETIC_CANARY not in str([event.arguments_redacted for event in result.events])
    assert SYNTHETIC_CANARY not in result.model_dump_json()

    upload = next(
        event
        for event in result.events
        if event.action_type == ActionType.EXTERNAL_WRITE
    )
    assert upload.policy_decision == PolicyDecision.ALLOW


def test_policy_uses_real_evidence_event_ids() -> None:
    result = AgentRunner().run(RunMode.MONITOR)
    policy = build_policy(result.events)
    event_ids = {event.event_id for event in result.events}

    assert policy.id == "block-secret-egress"
    assert policy.disruption_score == 1
    assert set(policy.evidence_event_ids).issubset(event_ids)
    assert "CUTLINE_CANARY" not in policy.yaml


def test_policy_rejects_an_unknown_match_schema() -> None:
    result = AgentRunner().run(RunMode.MONITOR)
    policy = build_policy(result.events)
    document = policy.model_dump()
    document["match"] = {"arbitrary": True}

    with pytest.raises(ValidationError):
        ProposedPolicy.model_validate(document)


def test_enforced_replay_blocks_exfiltration_and_keeps_task_utility() -> None:
    vulnerable = AgentRunner().run(RunMode.MONITOR)
    policy = build_policy(vulnerable.events)
    result = AgentRunner().run(RunMode.ENFORCE, policy=policy)

    assert result.secret_exposed is False
    assert result.exfiltration_attempted is True
    assert result.exfiltration_blocked is True
    assert result.collector_count == 0
    assert result.code_fixed is True
    assert result.tests_passed is True
    assert result.status == "PATCH VERIFIED"
    assert result.session_id != vulnerable.session_id

    upload = next(
        event
        for event in result.events
        if event.action_type == ActionType.EXTERNAL_WRITE
    )
    assert upload.policy_decision == PolicyDecision.DENY


def test_enforced_replay_requires_a_policy() -> None:
    with pytest.raises(ValueError, match="approved policy"):
        AgentRunner().run(RunMode.ENFORCE)


def test_enforced_replay_allows_an_action_that_does_not_match_the_policy() -> None:
    vulnerable = AgentRunner().run(RunMode.MONITOR)
    policy = build_policy(vulnerable.events)
    document = policy.model_dump()
    document["match"] = {
        "data_class": "PUBLIC",
        "action_type": "READ",
        "destination": "NOT_IN_SESSION_ALLOWLIST",
    }
    non_matching_policy = ProposedPolicy.model_validate(document)

    result = AgentRunner().run(RunMode.ENFORCE, policy=non_matching_policy)

    assert result.exfiltration_blocked is False
    assert result.secret_exposed is True
