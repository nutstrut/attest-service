"""Live SAR-402 ingestion verification against defaultverifier.com.

Builds payloads using the exact fixture shape from tests/test_sar402_receipts.py
(_base_payload / _unique_payload) and runs the required live checks. Read-only
against production: it only POSTs SAR-402 receipt payloads and GETs lookup routes.
"""
from __future__ import annotations

import hashlib
import json
import sys
import time
import urllib.request
import urllib.error

BASE = "https://defaultverifier.com"
TAGSEED = str(int(time.time()))


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


def http(method: str, url: str, body: dict | None = None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) sar402-live-verify/1.0")
    req.add_header("Accept", "application/json")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception as e:  # noqa: BLE001
        return None, f"ERROR: {e}"


def main():
    out = {}

    # 1+2+3. record-mode POST
    p = _unique_payload(f"liveaccept_{TAGSEED}")
    out["accept_digest"] = p["integrity"]["digest"]
    status, text = http("POST", f"{BASE}/v1/sar-402/receipts", p)
    out["accept_status"] = status
    out["accept_body"] = text

    receipt_id = None
    try:
        j = json.loads(text)
        receipt_id = j.get("receipt_id")
    except Exception:
        j = {}
    out["accept_json"] = j
    out["receipt_id"] = receipt_id

    # 5. lookup
    if receipt_id:
        import urllib.parse
        enc = urllib.parse.quote(receipt_id, safe="")
        s, t = http("GET", f"{BASE}/v1/attest/receipt/{enc}")
        out["lookup_status"] = s
        out["lookup_body"] = t

    # 6. recent receipts
    s, t = http("GET", f"{BASE}/v1/receipts")
    out["recent_status"] = s
    try:
        recent = json.loads(t)
        rids = [r.get("receipt_id") for r in recent.get("receipts", [])]
        out["recent_has_new"] = receipt_id in rids
        out["recent_count"] = len(rids)
    except Exception:
        out["recent_has_new"] = None
        out["recent_body"] = t[:500]

    # 7. authority hard rejection
    pa = _unique_payload(f"liveauth_{TAGSEED}")
    pa["authority_binding"]["verifier_has_execution_authority"] = True
    canonical = json.dumps(pa, sort_keys=True, separators=(",", ":"))
    pa["integrity"]["digest"] = "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
    auth_digest = pa["integrity"]["digest"]
    out["auth_digest"] = auth_digest
    s, t = http("POST", f"{BASE}/v1/sar-402/receipts", pa)
    out["auth_reject_status"] = s
    out["auth_reject_body"] = t
    # confirm not stored
    import urllib.parse
    enc = urllib.parse.quote(auth_digest, safe="")
    s2, t2 = http("GET", f"{BASE}/v1/attest/receipt/{enc}")
    out["auth_lookup_status"] = s2

    # 8. gate rejection
    pg = _unique_payload(f"livegate_{TAGSEED}")
    pg["verification_mode"] = "gate"
    canonical = json.dumps(pg, sort_keys=True, separators=(",", ":"))
    pg["integrity"]["digest"] = "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
    s, t = http("POST", f"{BASE}/v1/sar-402/receipts", pg)
    out["gate_reject_status"] = s
    out["gate_reject_body"] = t

    # 9. explorer url
    explorer = out.get("accept_json", {}).get("explorer_url")
    out["explorer_url"] = explorer
    if explorer:
        s, t = http("GET", explorer)
        out["explorer_status"] = s
        out["explorer_len"] = len(t)

    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
