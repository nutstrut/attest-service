"""EXEC-018 Option 3: provenance quarantine and trusted-history separation.

Definition-of-done coverage for `/v1/attest`-family submissions: an anonymous
caller cannot appear in any default trusted aggregate/history surface, and a
mechanical (not caller-claimed) signal is what decides provenance --
X-Forwarded-For / X-Real-IP presence, which only nginx's public proxy sets
(port 3004 is not reachable from the public internet; ufw is
default-deny-inbound, only 22/80/443 allowed -- see
reports/security/exec-018-public-attest-trust-contract-characterization-20260713.md
Sec.1 and the deployment evidence for this session's independent
reconfirmation).

All ledgers are monkeypatched to tmp_path. No production file is touched, no
production receipt or attestation is generated, no live network call is made
(post_json/get_json are monkeypatched per test).
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import attest_service as svc  # noqa: E402
from starlette.requests import Request  # noqa: E402

MORPHEUS_AGENT_ID = "agent:morpheus"
ATTACKER_AGENT_ID = "agent:morpheus"  # the attacker claims an existing agent's id


def _patch_ledgers(tmp_path, monkeypatch):
    for name in ("AGENT_LEDGER", "ACTIVATION_LEDGER", "CHAIN_LEDGER", "RECEIPT_LEDGER", "ANALYTICS_LEDGER", "SESSION_LEDGER"):
        monkeypatch.setattr(svc, name, tmp_path / f"{name.lower()}.jsonl")


def _register_agent(agent_id: str) -> dict:
    now = svc.iso_now()
    record = {
        "agent_id": agent_id,
        "display_name": agent_id,
        "owner_id": "owner:test",
        "counterparty": "counterparty:test",
        "registered_at": now,
        "created_at": now,
        "updated_at": now,
        "activation_stage": "registered",
        "stage": "registered",
        "status": "registered",
        "metadata": {},
    }
    svc.write_agent(record)
    return record


def _public_request(client_ip: str = "198.51.100.7") -> Request:
    """A request that arrived through nginx's public proxy (X-Forwarded-For
    set) -- the only way any external caller can reach this process."""
    scope = {
        "type": "http",
        "headers": [(b"x-forwarded-for", client_ip.encode()), (b"x-real-ip", client_ip.encode())],
        "client": (client_ip, 51515),
    }
    return Request(scope)


def _internal_request() -> Request:
    """A request with no forwarding headers, arriving from loopback -- only
    possible for a process already running on this host, since port 3004 is
    not reachable from the public internet and nginx always sets these
    headers for the public /v1/attest path."""
    scope = {"type": "http", "headers": [], "client": ("127.0.0.1", 44444)}
    return Request(scope)


def _fake_post_json(continuity_receipt="sha256:" + "1" * 64, sar_receipt="sha256:" + "2" * 64, verdict="PASS"):
    def fake(url, payload):
        if url == svc.CONTINUITY_EVALUATE_URL:
            return {"receipt_id": continuity_receipt}
        if url == svc.SAR_URL:
            return {"receipt_id": sar_receipt, "receipt_v0_1": {"verdict": verdict}}
        raise AssertionError(f"unexpected post_json url: {url}")
    return fake


# ---------------------------------------------------------------------------
# 1. Anonymous submission receives anonymous provenance; arbitrary claimed
#    agent_id remains untrusted attribution.
# ---------------------------------------------------------------------------

def test_public_attest_submission_is_classified_anonymous_untrusted(tmp_path, monkeypatch):
    _patch_ledgers(tmp_path, monkeypatch)
    monkeypatch.setattr(svc, "post_json", _fake_post_json())
    _register_agent(MORPHEUS_AGENT_ID)

    input_model = svc.SyncAttestInput(
        continuity_input={},
        sar_input={"task_id": "t1", "agent_id": ATTACKER_AGENT_ID},
    )
    result = svc.attest(input_model, request=_public_request())

    assert result["submission_provenance"] == "anonymous_untrusted"
    with open(tmp_path / "chain_ledger.jsonl") as f:
        stored_chain = json.loads(f.readline())
    assert stored_chain["agent_id"] == ATTACKER_AGENT_ID
    assert stored_chain["submission_provenance"] == "anonymous_untrusted"


def test_direct_loopback_call_without_forwarding_headers_is_trusted_internal(tmp_path, monkeypatch):
    _patch_ledgers(tmp_path, monkeypatch)
    monkeypatch.setattr(svc, "post_json", _fake_post_json())
    _register_agent(MORPHEUS_AGENT_ID)

    input_model = svc.SyncAttestInput(continuity_input={}, sar_input={"task_id": "t1", "agent_id": MORPHEUS_AGENT_ID})
    result = svc.attest(input_model, request=_internal_request())

    assert result["submission_provenance"] == "trusted_internal"


def test_missing_request_object_fails_closed_to_anonymous(tmp_path, monkeypatch):
    # A route invoked directly (no ASGI request at all) must never default to
    # a trusted class -- fail closed, not fail open.
    _patch_ledgers(tmp_path, monkeypatch)
    monkeypatch.setattr(svc, "post_json", _fake_post_json())
    _register_agent(MORPHEUS_AGENT_ID)

    input_model = svc.SyncAttestInput(continuity_input={}, sar_input={"task_id": "t1", "agent_id": MORPHEUS_AGENT_ID})
    result = svc.attest(input_model)

    assert result["submission_provenance"] == "anonymous_untrusted"


# ---------------------------------------------------------------------------
# 2. Anonymous record persists with provenance; default agent history /
#    aggregate counts / recent receipts all exclude it.
# ---------------------------------------------------------------------------

def test_default_agent_summary_excludes_anonymous_submission(tmp_path, monkeypatch):
    _patch_ledgers(tmp_path, monkeypatch)
    monkeypatch.setattr(svc, "post_json", _fake_post_json())
    _register_agent(MORPHEUS_AGENT_ID)

    input_model = svc.SyncAttestInput(continuity_input={}, sar_input={"task_id": "t1", "agent_id": MORPHEUS_AGENT_ID})
    svc.attest(input_model, request=_public_request())

    summary = svc.get_agent_summary(MORPHEUS_AGENT_ID, limit=50)
    assert summary["evidence_summary"]["receipt_count"] == 0
    assert summary["evidence_summary"]["chain_count"] == 0
    assert summary["evidence_summary"]["latest_chain_id"] is None
    assert summary["evidence_summary"]["provenance_scope"] == "trusted_evidence_only"
    assert summary["chains"] == []
    assert summary["receipts"] == []

    forensic = svc.get_agent_summary(MORPHEUS_AGENT_ID, limit=50, include_anonymous=True)
    assert forensic["evidence_summary"]["receipt_count"] >= 1
    assert forensic["evidence_summary"]["chain_count"] == 1
    assert forensic["evidence_summary"]["provenance_scope"] == "all_submissions_including_unverified"


def test_default_chains_and_receipts_listing_excludes_anonymous(tmp_path, monkeypatch):
    _patch_ledgers(tmp_path, monkeypatch)
    monkeypatch.setattr(svc, "post_json", _fake_post_json())
    _register_agent(MORPHEUS_AGENT_ID)
    svc.attest(
        svc.SyncAttestInput(continuity_input={}, sar_input={"task_id": "t1", "agent_id": MORPHEUS_AGENT_ID}),
        request=_public_request(),
    )

    assert svc.list_chains(limit=200)["count"] == 0
    assert svc.list_receipts(limit=200)["count"] == 0
    assert svc.list_chains(limit=200, include_anonymous=True)["count"] == 1
    assert svc.list_receipts(limit=200, include_anonymous=True)["count"] == 2  # continuity + sar


def test_default_explorer_metrics_excludes_anonymous_chain(tmp_path, monkeypatch):
    _patch_ledgers(tmp_path, monkeypatch)
    monkeypatch.setattr(svc, "post_json", _fake_post_json())
    _register_agent(MORPHEUS_AGENT_ID)
    svc.attest(
        svc.SyncAttestInput(continuity_input={}, sar_input={"task_id": "t1", "agent_id": MORPHEUS_AGENT_ID}),
        request=_public_request(),
    )

    metrics = svc.explorer_metrics()
    assert metrics["chains_total"] == 0
    assert metrics["provenance_scope"] == "trusted_evidence_only"

    forensic_metrics = svc.explorer_metrics(include_anonymous=True)
    assert forensic_metrics["chains_total"] == 1


def test_internal_direct_submission_appears_in_default_trusted_surfaces(tmp_path, monkeypatch):
    # The flip side of quarantine: legitimate internal traffic (Morpheus's
    # daily cycle, hermes-monitor, hitting 127.0.0.1:3004 directly) must not
    # be accidentally quarantined.
    _patch_ledgers(tmp_path, monkeypatch)
    monkeypatch.setattr(svc, "post_json", _fake_post_json())
    _register_agent(MORPHEUS_AGENT_ID)
    svc.attest(
        svc.SyncAttestInput(continuity_input={}, sar_input={"task_id": "t1", "agent_id": MORPHEUS_AGENT_ID}),
        request=_internal_request(),
    )

    summary = svc.get_agent_summary(MORPHEUS_AGENT_ID, limit=50)
    assert summary["evidence_summary"]["chain_count"] == 1
    assert svc.list_chains(limit=200)["count"] == 1
    assert svc.explorer_metrics()["chains_total"] == 1


# ---------------------------------------------------------------------------
# 3. /v1/attest/begin + /v1/attest/complete cannot be laundered into a
#    trusted record by mismatched provenance across the two calls.
# ---------------------------------------------------------------------------

def test_begin_public_then_complete_internal_remains_untrusted(tmp_path, monkeypatch):
    _patch_ledgers(tmp_path, monkeypatch)
    monkeypatch.setattr(svc, "post_json", _fake_post_json())
    _register_agent(MORPHEUS_AGENT_ID)

    begin_result = svc.begin(
        svc.BeginInput(continuity_input={}, receipt_context="real_task"),
        request=_public_request(),
    )
    complete_result = svc.complete(
        svc.CompleteInput(session_id=begin_result["session_id"], sar_input={"agent_id": MORPHEUS_AGENT_ID}),
        request=_internal_request(),
    )

    assert complete_result["status"] == "complete"
    with open(tmp_path / "chain_ledger.jsonl") as f:
        stored_chain = json.loads(f.readline())
    assert stored_chain["submission_provenance"] == "anonymous_untrusted"


def test_begin_internal_then_complete_internal_is_trusted(tmp_path, monkeypatch):
    _patch_ledgers(tmp_path, monkeypatch)
    monkeypatch.setattr(svc, "post_json", _fake_post_json())
    _register_agent(MORPHEUS_AGENT_ID)

    begin_result = svc.begin(
        svc.BeginInput(continuity_input={}, receipt_context="real_task"),
        request=_internal_request(),
    )
    complete_result = svc.complete(
        svc.CompleteInput(session_id=begin_result["session_id"], sar_input={"agent_id": MORPHEUS_AGENT_ID}),
        request=_internal_request(),
    )
    assert complete_result["status"] == "complete"
    with open(tmp_path / "chain_ledger.jsonl") as f:
        stored_chain = json.loads(f.readline())
    assert stored_chain["submission_provenance"] == "trusted_internal"


# ---------------------------------------------------------------------------
# 4. Legacy records (written before this field existed) are not silently
#    trusted, and are not silently promoted by direct mutation.
# ---------------------------------------------------------------------------

def test_legacy_record_without_field_is_legacy_unknown_and_excluded_by_default(tmp_path, monkeypatch):
    _patch_ledgers(tmp_path, monkeypatch)
    _register_agent(MORPHEUS_AGENT_ID)
    # Simulate a pre-existing ledger row written before this session's change:
    # no submission_provenance key at all.
    legacy_chain = {
        "chain_id": "sha256:" + "9" * 64,
        "agent_id": MORPHEUS_AGENT_ID,
        "continuity_receipt_id": "sha256:" + "a" * 64,
        "sar_receipt_id": "sha256:" + "b" * 64,
        "stage": "chained",
        "receipt_context": "real_task",
        "created_at": svc.iso_now(),
    }
    svc.append_jsonl(svc.CHAIN_LEDGER, legacy_chain)

    assert svc.record_submission_provenance(legacy_chain) == "legacy_unknown"
    assert svc.is_trusted_provenance(legacy_chain) is False
    assert svc.list_chains(limit=200)["count"] == 0
    assert svc.list_chains(limit=200, include_anonymous=True)["count"] == 1
    # The on-disk bytes are never rewritten to add the field.
    with open(tmp_path / "chain_ledger.jsonl") as f:
        raw = json.loads(f.readline())
    assert "submission_provenance" not in raw


def test_direct_ledger_mutation_to_claim_trusted_status_has_no_effect_on_other_records(tmp_path, monkeypatch):
    # Promotion is not a database edit: writing "submission_provenance":
    # "trusted_internal" onto one record must not affect how any other
    # record in the same ledger is classified.
    _patch_ledgers(tmp_path, monkeypatch)
    _register_agent(MORPHEUS_AGENT_ID)
    forged = {
        "chain_id": "sha256:" + "7" * 64,
        "agent_id": MORPHEUS_AGENT_ID,
        "continuity_receipt_id": "sha256:" + "c" * 64,
        "sar_receipt_id": "sha256:" + "d" * 64,
        "stage": "chained",
        "receipt_context": "real_task",
        "created_at": svc.iso_now(),
        "submission_provenance": "trusted_internal",
    }
    svc.append_jsonl(svc.CHAIN_LEDGER, forged)
    genuine_anonymous = {
        "chain_id": "sha256:" + "8" * 64,
        "agent_id": MORPHEUS_AGENT_ID,
        "continuity_receipt_id": "sha256:" + "e" * 64,
        "sar_receipt_id": "sha256:" + "f" * 64,
        "stage": "chained",
        "receipt_context": "real_task",
        "created_at": svc.iso_now(),
        "submission_provenance": "anonymous_untrusted",
    }
    svc.append_jsonl(svc.CHAIN_LEDGER, genuine_anonymous)

    chains = svc.list_chains(limit=200)["chains"]
    assert len(chains) == 1
    assert chains[0]["chain_id"] == forged["chain_id"]


# ---------------------------------------------------------------------------
# 5. Alternate write paths (activate, continuity-pair) get the same
#    treatment -- not asserted from a single code path.
# ---------------------------------------------------------------------------

def test_activate_agent_public_call_is_anonymous_and_excluded_by_default(tmp_path, monkeypatch):
    _patch_ledgers(tmp_path, monkeypatch)
    monkeypatch.setattr(svc, "post_json", _fake_post_json())
    _register_agent(MORPHEUS_AGENT_ID)

    result = svc.activate_agent(
        MORPHEUS_AGENT_ID,
        svc.ActivateAgentInput(continuity_input={}),
        request=_public_request(),
    )
    assert result["status"] == "complete"

    summary = svc.get_agent_summary(MORPHEUS_AGENT_ID, limit=50)
    assert summary["evidence_summary"]["chain_count"] == 0
    assert summary["evidence_summary"]["activation_count"] == 0
    forensic = svc.get_agent_summary(MORPHEUS_AGENT_ID, limit=50, include_anonymous=True)
    assert forensic["evidence_summary"]["chain_count"] == 1
    assert forensic["evidence_summary"]["activation_count"] == 1


def test_continuity_pair_public_call_is_anonymous_and_excluded_by_default(tmp_path, monkeypatch):
    _patch_ledgers(tmp_path, monkeypatch)
    monkeypatch.setattr(svc, "post_json", _fake_post_json())
    _register_agent(MORPHEUS_AGENT_ID)
    svc.activate_agent(
        MORPHEUS_AGENT_ID,
        svc.ActivateAgentInput(continuity_input={}),
        request=_internal_request(),
    )

    result = svc.record_continuity_pair(
        MORPHEUS_AGENT_ID,
        svc.ContinuityPairInput(continuity_input={}),
        request=_public_request(),
    )
    assert result["stage"] == "continuous"

    summary = svc.get_agent_summary(MORPHEUS_AGENT_ID, limit=50)
    # The internal activation is trusted; the anonymous continuity-pair chain
    # it produced is not.
    assert summary["evidence_summary"]["chain_count"] == 1
    forensic = svc.get_agent_summary(MORPHEUS_AGENT_ID, limit=50, include_anonymous=True)
    assert forensic["evidence_summary"]["chain_count"] == 2


# ---------------------------------------------------------------------------
# 6. Compatibility path: the shared SAR-402 public ingestion route
#    (/v1/sar-402/receipts, also unauthenticated by default) writes through
#    the same write_receipt() machinery and must not reintroduce anonymous
#    evidence into the default trusted receipt listing either.
# ---------------------------------------------------------------------------

def test_sar402_receipt_without_explicit_provenance_defaults_to_anonymous(tmp_path, monkeypatch):
    _patch_ledgers(tmp_path, monkeypatch)

    svc.write_receipt(
        receipt={"receipt_id": "sha256:" + "3" * 64},
        receipt_type="sar_402_settlement",
        receipt_context="real_task",
        agent_id=MORPHEUS_AGENT_ID,
    )

    assert svc.list_receipts(limit=200)["count"] == 0
    assert svc.list_receipts(limit=200, include_anonymous=True)["count"] == 1


# ---------------------------------------------------------------------------
# 7. No reputation/quality vocabulary leaks into the provenance surface.
# ---------------------------------------------------------------------------

def test_no_reputation_vocabulary_in_provenance_classes():
    forbidden = {"score", "reputation", "ranking", "quality", "confidence_tier", "trust_level"}
    for value in svc.TRUSTED_PROVENANCE_CLASSES | {"anonymous_untrusted", svc.LEGACY_UNKNOWN_PROVENANCE}:
        assert not any(word in value for word in forbidden)
