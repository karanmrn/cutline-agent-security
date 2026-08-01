from __future__ import annotations

from app.models import ActionType, EvidenceGraph, Event, GraphEdge, GraphNode


def build_evidence_graph(events: list[Event]) -> EvidenceGraph:
    instruction = next(
        (event for event in events if event.tool_name == "read_workspace_rule"), None
    )
    secret_read = next(
        (
            event
            for event in events
            if event.tool_name == "read_file" and event.data_class.value == "SECRET"
        ),
        None,
    )
    upload = next(
        (event for event in events if event.action_type == ActionType.EXTERNAL_WRITE),
        None,
    )
    fix = next((event for event in events if event.tool_name == "write_file"), None)
    tests = next((event for event in events if event.tool_name == "run_tests"), None)

    nodes = [
        GraphNode(
            id="user-task",
            label="Trusted user task",
            kind="instruction",
            status="safe",
        )
    ]
    edges: list[GraphEdge] = []

    if instruction:
        nodes.append(
            GraphNode(
                id="workspace-rule",
                label="Untrusted workspace rule",
                kind="instruction",
                status="danger",
                event_id=instruction.event_id,
            )
        )
    if secret_read:
        nodes.append(
            GraphNode(
                id="secret-read",
                label="Synthetic secret read",
                kind="data",
                status="danger",
                event_id=secret_read.event_id,
            )
        )
    if upload:
        upload_status = "blocked" if upload.policy_decision.value == "DENY" else "danger"
        nodes.append(
            GraphNode(
                id="external-write",
                label=(
                    "External write blocked"
                    if upload_status == "blocked"
                    else "Synthetic canary exposed"
                ),
                kind="sink",
                status=upload_status,
                event_id=upload.event_id,
            )
        )
    if fix:
        nodes.append(
            GraphNode(
                id="code-fix",
                label="Application bug fixed",
                kind="action",
                status="safe",
                event_id=fix.event_id,
            )
        )
    if tests:
        nodes.append(
            GraphNode(
                id="tests",
                label="Unit tests passed" if tests.outcome == "success" else "Tests failed",
                kind="result",
                status="safe" if tests.outcome == "success" else "danger",
                event_id=tests.event_id,
            )
        )

    if instruction and secret_read:
        edges.append(
            GraphEdge(
                source="workspace-rule",
                target="secret-read",
                label="influenced",
                status="danger",
            )
        )
    if secret_read and upload:
        edges.append(
            GraphEdge(
                source="secret-read",
                target="external-write",
                label="data flow",
                status="blocked" if upload.policy_decision.value == "DENY" else "danger",
            )
        )
    if fix:
        edges.append(
            GraphEdge(
                source="user-task",
                target="code-fix",
                label="legitimate path",
                status="safe",
            )
        )
    if fix and tests:
        edges.append(
            GraphEdge(
                source="code-fix",
                target="tests",
                label="verified by",
                status="safe",
            )
        )

    return EvidenceGraph(nodes=nodes, edges=edges)
