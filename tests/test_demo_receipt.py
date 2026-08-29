import time

import attest_service as svc
from fastapi.testclient import TestClient


def _reset_rate_state():
    svc._demo_rate_state.clear()


def test_demo_receipt_forces_fixed_shape_and_no_secret_reaches_client(monkeypatch):
    _reset_rate_state()
    monkeypatch.setenv("SETTLEMENT_ATTEST_API_KEY", "server-only-secret-value")

    captured = {}

    def fake_post_json(url, payload, *, headers=None):
        captured["url"] = url
        captured["payload"] = payload
        captured["headers"] = headers
        return {
            "receipt_id": "sha256:deadbeef",
            "verdict": "PASS",
            "reason_code": "CONDITION_SATISFIED",
            "verifier_kid": "sar-prod-ed25519-06",
            "ts": "2026-08-29T00:00:00Z",
            "sig": "base64:abc",
        }

    monkeypatch.setattr(svc, "post_json", fake_post_json)

    client = TestClient(svc.app)
    resp = client.post("/v1/demo-receipt")

    assert resp.status_code == 200
    body = resp.json()

    # Canonical v0.2 request shape, forced server-side -- nothing caller-controlled.
    assert captured["url"] == svc.SAR_URL
    assert captured["payload"]["agent_id"] == "demo-agent"
    assert captured["payload"]["spec"] == svc.DEMO_SPEC
    assert captured["payload"]["output"] == svc.DEMO_OUTPUT

    # The server-only secret must never appear in the response body.
    assert "server-only-secret-value" not in resp.text
    assert "Authorization" not in body
    assert "SETTLEMENT_ATTEST_API_KEY" not in resp.text

    # The auth header sent upstream carries the secret -- but that header is
    # server-to-server only, never returned to the client.
    assert captured["headers"]["Authorization"] == "Bearer server-only-secret-value"
    assert "X-Settlement-Timestamp" in captured["headers"]
    assert "X-Settlement-Nonce" in captured["headers"]

    assert body["receipt_id"] == "sha256:deadbeef"
    assert body["agent_id"] == "demo-agent"


def test_demo_receipt_ignores_arbitrary_caller_body(monkeypatch):
    """Even if a caller sends a body trying to override agent_id/checks, the
    route takes no request body model at all -- nothing to inject into."""
    _reset_rate_state()
    monkeypatch.setenv("SETTLEMENT_ATTEST_API_KEY", "secret")
    captured = {}

    def fake_post_json(url, payload, *, headers=None):
        captured["payload"] = payload
        return {"receipt_id": "sha256:x", "verdict": "PASS"}

    monkeypatch.setattr(svc, "post_json", fake_post_json)
    client = TestClient(svc.app)
    resp = client.post(
        "/v1/demo-receipt",
        json={"agent_id": "attacker-agent", "spec": {"checks": [{"kind": "arbitrary"}]}},
    )
    assert resp.status_code == 200
    assert captured["payload"]["agent_id"] == "demo-agent"
    assert captured["payload"]["spec"] == svc.DEMO_SPEC


def test_demo_receipt_upstream_401_is_handled_safely(monkeypatch):
    _reset_rate_state()
    monkeypatch.setenv("SETTLEMENT_ATTEST_API_KEY", "secret")

    from fastapi import HTTPException

    def fake_post_json(url, payload, *, headers=None):
        raise HTTPException(status_code=401, detail={"result": "UNAUTHORIZED"})

    monkeypatch.setattr(svc, "post_json", fake_post_json)
    client = TestClient(svc.app)
    resp = client.post("/v1/demo-receipt")
    assert resp.status_code == 502
    assert resp.json()["detail"] == {"result": "DEMO_ISSUANCE_FAILED"}
    # no upstream detail (which could carry internal info) is echoed
    assert "UNAUTHORIZED" not in resp.text


def test_demo_receipt_missing_upstream_receipt_id_fails_safely(monkeypatch):
    _reset_rate_state()
    monkeypatch.setenv("SETTLEMENT_ATTEST_API_KEY", "secret")

    def fake_post_json(url, payload, *, headers=None):
        return {"verdict": "PASS"}  # no receipt_id

    monkeypatch.setattr(svc, "post_json", fake_post_json)
    client = TestClient(svc.app)
    resp = client.post("/v1/demo-receipt")
    assert resp.status_code == 502


def test_demo_receipt_rate_limited_per_ip(monkeypatch):
    _reset_rate_state()
    monkeypatch.setenv("SETTLEMENT_ATTEST_API_KEY", "secret")

    def fake_post_json(url, payload, *, headers=None):
        return {"receipt_id": "sha256:x", "verdict": "PASS"}

    monkeypatch.setattr(svc, "post_json", fake_post_json)
    client = TestClient(svc.app)

    statuses = [client.post("/v1/demo-receipt").status_code for _ in range(svc.DEMO_RATE_LIMIT_MAX_PER_IP + 2)]
    assert statuses[: svc.DEMO_RATE_LIMIT_MAX_PER_IP] == [200] * svc.DEMO_RATE_LIMIT_MAX_PER_IP
    assert statuses[svc.DEMO_RATE_LIMIT_MAX_PER_IP] == 429


def test_demo_rate_limit_window_expires():
    _reset_rate_state()
    now = time.time()
    for _ in range(svc.DEMO_RATE_LIMIT_MAX_PER_IP):
        assert svc._demo_rate_limited("1.2.3.4", now=now) is False
    assert svc._demo_rate_limited("1.2.3.4", now=now) is True
    later = now + svc.DEMO_RATE_LIMIT_WINDOW_SECONDS + 1
    assert svc._demo_rate_limited("1.2.3.4", now=later) is False
