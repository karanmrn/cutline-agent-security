from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_three_step_api_flow() -> None:
    reset = client.post("/api/demo/reset")
    assert reset.status_code == 200

    vulnerable = client.post("/api/demo/run-vulnerable")
    assert vulnerable.status_code == 200
    assert vulnerable.json()["vulnerable_run"]["secret_exposed"] is True

    policy = client.post("/api/demo/generate-policy")
    assert policy.status_code == 200
    proposed_policy = policy.json()["proposed_policy"]
    assert proposed_policy["id"] == "block-secret-egress"

    replay = client.post(
        "/api/demo/replay",
        json={
            "approved": True,
            "policy_id": proposed_policy["id"],
            "policy_version": proposed_policy["version"],
        },
    )
    assert replay.status_code == 200
    body = replay.json()
    assert body["replay_run"]["secret_exposed"] is False
    assert body["replay_run"]["tests_passed"] is True


def test_policy_requires_vulnerable_run() -> None:
    client.post("/api/demo/reset")
    response = client.post("/api/demo/generate-policy")
    assert response.status_code == 409


def test_replay_requires_explicit_policy_approval() -> None:
    client.post("/api/demo/reset")
    client.post("/api/demo/run-vulnerable")
    client.post("/api/demo/generate-policy")

    response = client.post("/api/demo/replay")

    assert response.status_code == 422


def test_replay_rejects_approval_for_a_different_policy() -> None:
    client.post("/api/demo/reset")
    client.post("/api/demo/run-vulnerable")
    client.post("/api/demo/generate-policy")

    response = client.post(
        "/api/demo/replay",
        json={
            "approved": True,
            "policy_id": "different-policy",
            "policy_version": 1,
        },
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "Approve the currently proposed guardrail before replay."
