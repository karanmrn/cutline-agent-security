import pytest
from pydantic import ValidationError

from app.models import ActionType, PolicyDecision, ProposedPolicy, RunMode
from app.policy import build_policy, evaluate_external_write
from app.runner import SYNTHETIC_CANARY, AgentRunner


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


def test_policy_rejects_events_without_a_parent_linked_attack_chain() -> None:
    result = AgentRunner().run(RunMode.MONITOR)
    events = list(result.events)
    upload_index = next(
        index
        for index, event in enumerate(events)
        if event.action_type == ActionType.EXTERNAL_WRITE
    )
    events[upload_index] = events[upload_index].model_copy(
        update={"parent_event_id": events[0].event_id}
    )

    with pytest.raises(ValueError, match="evidence path is incomplete"):
        build_policy(events)


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


def test_graph_trusted_task_node_cites_its_event() -> None:
    result = AgentRunner().run(RunMode.MONITOR)
    root = next(node for node in result.graph.nodes if node.id == "user-task")

    assert root.event_id == result.events[0].event_id


def test_policy_allows_a_destination_authorized_for_this_session() -> None:
    vulnerable = AgentRunner().run(RunMode.MONITOR)
    policy = build_policy(vulnerable.events)

    decision = evaluate_external_write(
        action_type=ActionType.EXTERNAL_WRITE,
        data_class=policy.match.data_class,
        destination="external-support",
        session_allowlist={"external-support"},
        policy=policy,
    )

    assert decision == PolicyDecision.ALLOW


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
