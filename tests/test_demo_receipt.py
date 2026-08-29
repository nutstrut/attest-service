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


# --- Real-backend response-shape contract (2026-08-29 second deployment    ---
# --- attempt smoke test) ----------------------------------------------------
#
# The first deployment attempt's defect was structural: demo_receipt() called
# SAR_URL + "/attest" (a JWS-wrapped envelope endpoint with no top-level
# receipt_id) instead of SAR_URL (the endpoint every other D31 call site
# uses, which returns the receipt dict directly). The adapter's own
# sar.get("receipt_id") check masked this -- it always returned None and was
# reported as DEMO_ISSUANCE_FAILED, even though a real, validly-signed
# receipt was issued server-side each time (confirmed:
# sha256:6e2138a96e7ac0e7b0ac54c8fc4e985bd6aa8d600bd8c3dd13493a4c44bec43d from
# the first attempt's diagnostic, sha256:593dcea628eb918f5d826e601f7c81d657cf94fce328a082b4cb22e4abf14492
# from this pass's mandatory real-backend smoke test against the corrected
# SAR_URL target).
#
# REAL_SETTLEMENT_WITNESS_RESPONSE below is the exact top-level key set
# observed from that real backend call, used as a fixture so this test does
# not depend on network access but still pins the true contract.
REAL_SETTLEMENT_WITNESS_RESPONSE = {
    "receipt_id": "sha256:593dcea628eb918f5d826e601f7c81d657cf94fce328a082b4cb22e4abf14492",
    "verdict": "PASS",
    "reason_code": "CONDITION_SATISFIED",
    "verifier_kid": "sar-prod-ed25519-06",
    "ts": "2026-08-29T20:00:00Z",
    "sig": "base64url:deadbeef",
    "sig_alg": "EdDSA",
    "receipt_profile": "v0.2",
    "receipt_version": "0.2",
    "verification_basis": "deterministic",
    "payment": None,
    "properties": {},
    "_unsigned": {},
}

# The JWS-wrapped /settlement-witness/attest shape that caused the first
# attempt's defect -- has NO top-level receipt_id. A correct adapter must
# treat this as a failure, not silently extract something wrong from it.
WRONG_ENDPOINT_ENVELOPE_RESPONSE = {
    "issuer": "https://defaultverifier.com",
    "type": "settlement_witness",
    "kid": "sar-prod-ed25519-06",
    "alg": "EdDSA",
    "jwks": "https://defaultverifier.com/.well-known/jwks.json",
    "jws": "eyJ...",
    "payload": {"receipt_id": "sha256:nested-not-top-level"},
    "envelope": {"receipt_id": "sha256:nested-not-top-level"},
}


def test_demo_receipt_targets_the_bare_sar_url_not_the_attest_suffix(monkeypatch):
    """Pins the exact fix for the first deployment attempt's defect: the demo
    route must call the same endpoint as the other three D31 call sites."""
    _reset_rate_state()
    monkeypatch.setenv("SETTLEMENT_ATTEST_API_KEY", "k")
    captured = {}

    def fake_post_json(url, payload, *, headers=None):
        captured["url"] = url
        return dict(REAL_SETTLEMENT_WITNESS_RESPONSE)

    monkeypatch.setattr(svc, "post_json", fake_post_json)
    client = TestClient(svc.app)
    resp = client.post("/v1/demo-receipt")

    assert captured["url"] == svc.SAR_URL
    assert captured["url"] != svc.SAR_URL + "/attest"
    assert resp.status_code == 200


def test_demo_receipt_extracts_receipt_id_from_real_backend_shape(monkeypatch):
    """Contract test against the actual observed real-backend response shape
    (fixture captured from a live smoke-test call, not invented)."""
    _reset_rate_state()
    monkeypatch.setenv("SETTLEMENT_ATTEST_API_KEY", "k")
    monkeypatch.setattr(svc, "post_json", lambda url, payload, *, headers=None: dict(REAL_SETTLEMENT_WITNESS_RESPONSE))

    client = TestClient(svc.app)
    resp = client.post("/v1/demo-receipt")

    assert resp.status_code == 200
    body = resp.json()
    assert body["receipt_id"] == REAL_SETTLEMENT_WITNESS_RESPONSE["receipt_id"]
    assert body["verdict"] == "PASS"
    assert body["verifier_kid"] == "sar-prod-ed25519-06"


def test_demo_receipt_reports_failure_not_false_success_on_wrapped_envelope_shape(monkeypatch):
    """Regression guard: if the adapter is ever pointed back at an endpoint
    that returns a JWS-wrapped envelope with no top-level receipt_id, it must
    fail loudly (502 DEMO_ISSUANCE_FAILED) rather than silently succeed with a
    missing/garbage receipt_id -- and it must never report success while
    quietly issuing an unreported real receipt, which is exactly what the
    first deployment attempt did."""
    _reset_rate_state()
    monkeypatch.setenv("SETTLEMENT_ATTEST_API_KEY", "k")
    monkeypatch.setattr(
        svc, "post_json", lambda url, payload, *, headers=None: dict(WRONG_ENDPOINT_ENVELOPE_RESPONSE)
    )

    client = TestClient(svc.app)
    resp = client.post("/v1/demo-receipt")

    assert resp.status_code == 502
    assert resp.json()["detail"]["result"] == "DEMO_ISSUANCE_FAILED"
