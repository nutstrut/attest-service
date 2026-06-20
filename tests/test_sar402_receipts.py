"""Tests for the public SAR-402 ingestion endpoint: POST /v1/sar-402/receipts.

These exercise the testable core (`record_sar402_receipt`) directly — no live
network, no TestClient (httpx is not a dependency). They prove: valid payloads
are accepted and persisted into the same ledger Explorer reads; required fields
are enforced; false authority claims and gate mode are HARD-rejected with no
receipt stored; the optional API key is enforced only when configured; and the
receipt is discoverable via the live lookup route + recent-receipts surface.
"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import attest_service as svc  # noqa: E402
from sar402_receipts import (  # noqa: E402
    record_sar402_receipt,
    schema_projection,
)
from morpheus.sar402.validate import validate_receipt  # noqa: E402


# ---------------------------------------------------------------------------
# A valid, SDK-shaped SAR-402 payload (authority binding as the SDK emits it).
# ---------------------------------------------------------------------------

def _base_payload() -> dict:
    payload = {
        "schema_id": "sar_402_settlement_v0.1",
        "profile": "sar-402",
        "sar_type": "Settlement Attestation Receipt",
        "sar_verdict": "PASS",
        "verification_point": "post_delivery",
        "verification_mode": "record",
        "authority_binding": {
            "verifier_has_execution_authority": False,
            "verifier_controls_resource_release": False,
            "resource_server_controls_delivery": True,
            "acting_party": "resource_server",
        },
        "payment_state": "verified",
        "delivery_state": "confirmed",
        "settlement_state": "delivered",
        "continuity": {
            "object_continuity": "PASS",
            "constraint_continuity": "PASS",
            "temporal_continuity": "PASS",
            "authority_continuity": "PASS",
            "executor_continuity": "PASS",
        },
        "payment": {
            "resource": "https://api.example.com/v1/summary",
            "quote_id": "q_test_1",
            "price": {"amount": "10000", "asset": "USDC", "decimals": 6},
            "amount_paid": {"amount": "10000", "asset": "USDC", "decimals": 6},
            "asset": "USDC",
            "chain": "eip155:8453",
            "recipient": "0xRECIPIENT00000000000000000000000000000001",
            "payer": "0xPAYER0000000000000000000000000000000002",
            "payment_ref": "0xdeadbeef",
        },
        "delivery": {
            "delivered_resource": "https://api.example.com/v1/summary",
            "evidence_type": "http_response",
            "evidence_digest": "sha256:" + "a" * 64,
            "status_code": 200,
            "delivered_at": "2026-06-20T12:00:00Z",
        },
        "identity": {
            "payer": "0xPAYER0000000000000000000000000000000002",
            "derived_identity": {
                "registration_mode": "derived_from_settlement",
                "derived_agent_id": "agent:x402:eip155:8453:0xPAYER0000000000000000000000000000000002",
                "identity_status": "derived",
            },
        },
        "timestamps": {
            "quoted_at": "2026-06-20T11:59:30Z",
            "paid_at": "2026-06-20T11:59:58Z",
            "verified_at": "2026-06-20T12:00:01Z",
            "delivered_at": "2026-06-20T12:00:00Z",
            "issued_at": "2026-06-20T12:00:01Z",
            "quote_expires_at": "2026-06-20T12:09:30Z",
        },
        "issuer": {
            "verifier": "DefaultVerifier",
            "verifier_version": "0.1.0",
            "environment": "test",
        },
    }
    # A unique integrity digest per payload (so each test gets a fresh id).
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    digest = "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
    payload["integrity"] = {
        "digest_alg": "sha256",
        "canonicalization": "sorted_keys_compact_v0",
        "digest": digest,
    }
    return payload


def _unique_payload(tag: str) -> dict:
    payload = _base_payload()
    payload["payment"]["quote_id"] = f"q_{tag}"
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    payload["integrity"]["digest"] = "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
    return payload


# ---------------------------------------------------------------------------
# Acceptance + persistence + Explorer compatibility
# ---------------------------------------------------------------------------

def test_valid_payload_accepted_and_has_receipt_id_and_explorer_url():
    result = record_sar402_receipt(_unique_payload("accept"))
    assert result["status"] == "recorded"
    assert result["receipt_id"].startswith("sha256:")  # requirement 5
    assert result["explorer_url"].startswith("http")    # requirement 6
    assert result["explorer_url"].endswith(result["receipt_id"].replace(":", "%3A"))
    assert result["profile"] == "sar-402"
    assert result["schema_id"] == "sar_402_settlement_v0.1"
    assert result["mode"] == "record"


def test_projection_passes_committed_validator():
    # The schema-conformant projection must satisfy the committed validator.
    validate_receipt(schema_projection(_unique_payload("proj")))


def test_receipt_is_persisted_and_discoverable(tmp_path, monkeypatch):
    # Point the receipt ledger at a temp file so Explorer-surface lookups are
    # deterministic and isolated.
    ledger = tmp_path / "receipts.jsonl"
    monkeypatch.setattr(svc, "RECEIPT_LEDGER", ledger)

    payload = _unique_payload("persist")
    result = record_sar402_receipt(payload)
    receipt_id = result["receipt_id"]

    # Same store Explorer reads: looked up by id via the live route helper.
    found = svc.find_receipt(receipt_id)
    assert found is not None
    assert found["receipt_id"] == receipt_id
    # /v1/attest/receipt/{id} returns it (not a dead link).
    assert svc.get_receipt(receipt_id)["receipt_id"] == receipt_id
    # Recent-receipts surface (/v1/receipts) includes it.
    recent = svc.list_receipts(limit=200)
    assert any(r["receipt_id"] == receipt_id for r in recent["receipts"])
    # The returned lookup path targets that live route.
    assert result["receipt_lookup_path"].endswith(receipt_id.replace(":", "%3A"))


# ---------------------------------------------------------------------------
# Rejections (each must store nothing and produce no Explorer link)
# ---------------------------------------------------------------------------

def _assert_nothing_stored(ledger: Path):
    if not ledger.exists():
        return
    assert ledger.read_text().strip() == ""


def test_missing_required_field_rejected(tmp_path, monkeypatch):
    ledger = tmp_path / "receipts.jsonl"
    monkeypatch.setattr(svc, "RECEIPT_LEDGER", ledger)
    payload = _unique_payload("missing")
    del payload["payment"]  # required by the committed schema
    with pytest.raises(HTTPException) as exc:
        record_sar402_receipt(payload)
    assert exc.value.status_code == 422
    _assert_nothing_stored(ledger)


def test_verifier_execution_authority_true_rejected(tmp_path, monkeypatch):
    ledger = tmp_path / "receipts.jsonl"
    monkeypatch.setattr(svc, "RECEIPT_LEDGER", ledger)
    payload = _unique_payload("authexec")
    payload["authority_binding"]["verifier_has_execution_authority"] = True
    with pytest.raises(HTTPException) as exc:
        record_sar402_receipt(payload)
    assert exc.value.status_code == 422
    # No receipt stored, no explorer link produced.
    _assert_nothing_stored(ledger)
    assert svc.find_receipt(payload["integrity"]["digest"]) is None


def test_verifier_controls_resource_release_true_rejected(tmp_path, monkeypatch):
    ledger = tmp_path / "receipts.jsonl"
    monkeypatch.setattr(svc, "RECEIPT_LEDGER", ledger)
    payload = _unique_payload("release")
    payload["authority_binding"]["verifier_controls_resource_release"] = True
    with pytest.raises(HTTPException) as exc:
        record_sar402_receipt(payload)
    assert exc.value.status_code == 422
    _assert_nothing_stored(ledger)


def test_resource_server_controls_delivery_false_rejected():
    payload = _unique_payload("delivctrl")
    payload["authority_binding"]["resource_server_controls_delivery"] = False
    with pytest.raises(HTTPException) as exc:
        record_sar402_receipt(payload, persist=False)
    assert exc.value.status_code == 422


def test_gate_mode_rejected(tmp_path, monkeypatch):
    ledger = tmp_path / "receipts.jsonl"
    monkeypatch.setattr(svc, "RECEIPT_LEDGER", ledger)
    payload = _unique_payload("gate")
    payload["verification_mode"] = "gate"
    with pytest.raises(HTTPException) as exc:
        record_sar402_receipt(payload)
    assert exc.value.status_code == 422
    _assert_nothing_stored(ledger)


def test_missing_integrity_digest_rejected():
    payload = _unique_payload("noint")
    del payload["integrity"]
    with pytest.raises(HTTPException) as exc:
        record_sar402_receipt(payload, persist=False)
    assert exc.value.status_code == 422


# ---------------------------------------------------------------------------
# Privacy default: raw bodies are not required
# ---------------------------------------------------------------------------

def test_raw_bodies_not_required():
    payload = _unique_payload("nobody")
    # No request_digest, no raw request/response body fields present.
    assert "request_digest" not in payload
    result = record_sar402_receipt(payload, persist=False)
    assert result["status"] == "recorded"


# ---------------------------------------------------------------------------
# Optional API key (Option B)
# ---------------------------------------------------------------------------

def test_api_key_enforced_only_when_configured():
    payload = _unique_payload("auth")
    env = {"SAR402_INGEST_API_KEY": "secret-key"}
    # Missing / wrong key -> 401.
    with pytest.raises(HTTPException) as exc:
        record_sar402_receipt(payload, env=env, persist=False)
    assert exc.value.status_code == 401
    with pytest.raises(HTTPException):
        record_sar402_receipt(payload, authorization="Bearer nope", env=env, persist=False)
    # Correct key -> accepted.
    ok = record_sar402_receipt(
        payload, authorization="Bearer secret-key", env=env, persist=False
    )
    assert ok["status"] == "recorded"
    # Unset key -> open (early adopter).
    open_ok = record_sar402_receipt(payload, env={}, persist=False)
    assert open_ok["status"] == "recorded"
