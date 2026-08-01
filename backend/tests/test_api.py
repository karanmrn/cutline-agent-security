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
    incident = policy.json()["incident"]
    assert incident["source_session_id"] == vulnerable.json()["vulnerable_run"]["session_id"]
    assert incident["evidence_event_ids"] == proposed_policy["evidence_event_ids"]
    assert incident["attack_path_verified"] is True

    replay = client.post(
        "/api/demo/replay",
        json={
            "approved": True,
            "policy_id": proposed_policy["id"],
            "policy_version": proposed_policy["version"],
            "policy_hash": proposed_policy["policy_hash"],
            "provider": "local",
        },
    )
    assert replay.status_code == 200
    body = replay.json()
    assert body["replay_run"]["secret_exposed"] is False
    assert body["replay_run"]["tests_passed"] is True
    assert body["vulnerable_run"]["fixture_id"] != body["replay_run"]["fixture_id"]
    manifest = body["regression_manifest"]
    assert set(manifest) == {
        "schema_version",
        "scenario_id",
        "scenario_version",
        "source_session_id",
        "source_fixture_id",
        "replay_session_id",
        "replay_fixture_id",
        "policy_id",
        "policy_version",
        "policy_hash",
        "evidence_event_ids",
        "assertions",
        "digest_sha256",
    }
    assert manifest["schema_version"] == 1
    assert manifest["scenario_id"] == "workspace-rule-secret-egress"
    assert manifest["scenario_version"] == 1
    assert manifest["source_session_id"] == body["vulnerable_run"]["session_id"]
    assert manifest["source_fixture_id"] == body["vulnerable_run"]["fixture_id"]
    assert manifest["replay_session_id"] == body["replay_run"]["session_id"]
    assert manifest["replay_fixture_id"] == body["replay_run"]["fixture_id"]
    assert manifest["policy_id"] == proposed_policy["id"]
    assert manifest["policy_version"] == proposed_policy["version"]
    assert manifest["policy_hash"] == proposed_policy["policy_hash"]
    assert set(proposed_policy["evidence_event_ids"]).issubset(
        manifest["evidence_event_ids"]
    )
    assert manifest["assertions"] == {
        "attack_attempted": True,
        "attack_blocked": True,
        "secret_exposed": False,
        "code_fixed": True,
        "tests_passed": True,
    }
    assert len(manifest["digest_sha256"]) == 64

    download = client.get("/api/demo/regression-manifest")
    assert download.status_code == 200
    assert download.json() == manifest


def test_regression_manifest_requires_a_verified_replay() -> None:
    client.post("/api/demo/reset")

    response = client.get("/api/demo/regression-manifest")

    assert response.status_code == 409


def test_state_reports_modal_as_unverified_before_a_smoke_test() -> None:
    client.post("/api/demo/reset")

    modal = client.get("/api/state").json()["integrations"]["modal"]

    assert modal["provider"] == "modal"
    assert modal["state"] == "unverified"
    assert modal["configured"] is False
    assert modal["last_checked_at"] is None
    assert isinstance(modal["message"], str)
    assert set(modal) == {
        "provider",
        "state",
        "configured",
        "last_checked_at",
        "message",
    }


def test_modal_enablement_reports_configured_but_not_verified(monkeypatch) -> None:
    monkeypatch.setenv("CUTLINE_MODAL_ENABLED", "1")

    modal = client.get("/api/state").json()["integrations"]["modal"]

    assert modal["state"] == "unverified"
    assert modal["configured"] is True
    assert set(modal) == {
        "provider",
        "state",
        "configured",
        "last_checked_at",
        "message",
    }


def test_modal_replay_never_silently_falls_back_to_local() -> None:
    client.post("/api/demo/reset")
    client.post("/api/demo/run-vulnerable")
    policy = client.post("/api/demo/generate-policy").json()["proposed_policy"]

    response = client.post(
        "/api/demo/replay",
        json={
            "approved": True,
            "policy_id": policy["id"],
            "policy_version": policy["version"],
            "policy_hash": policy["policy_hash"],
            "provider": "modal",
        },
    )

    assert response.status_code == 503
    assert "Modal" in response.json()["detail"]
    assert client.get("/api/state").json()["replay_run"] is None


def test_failed_disabled_modal_replay_preserves_configuration_truth_and_resets(
    monkeypatch,
) -> None:
    monkeypatch.delenv("CUTLINE_MODAL_ENABLED", raising=False)
    client.post("/api/demo/reset")
    client.post("/api/demo/run-vulnerable")
    policy = client.post("/api/demo/generate-policy").json()["proposed_policy"]

    response = client.post(
        "/api/demo/replay",
        json={
            "approved": True,
            "policy_id": policy["id"],
            "policy_version": policy["version"],
            "policy_hash": policy["policy_hash"],
            "provider": "modal",
        },
    )

    assert response.status_code == 503
    failed = client.get("/api/state").json()["integrations"]["modal"]
    assert failed["state"] == "error"
    assert failed["configured"] is False

    reset = client.post("/api/demo/reset").json()["integrations"]["modal"]
    assert reset["state"] == "unverified"
    assert reset["configured"] is False
    assert reset["last_checked_at"] is None


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
            "policy_hash": "0" * 64,
            "provider": "local",
        },
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "Approve the currently proposed guardrail before replay."


def test_replay_rejects_approval_for_an_altered_policy_hash() -> None:
    client.post("/api/demo/reset")
    client.post("/api/demo/run-vulnerable")
    policy = client.post("/api/demo/generate-policy").json()["proposed_policy"]

    response = client.post(
        "/api/demo/replay",
        json={
            "approved": True,
            "policy_id": policy["id"],
            "policy_version": policy["version"],
            "policy_hash": "0" * 64,
            "provider": "local",
        },
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "Approve the currently proposed guardrail before replay."
