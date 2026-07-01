"""Tests for the Phase 2 read-only chain correlation view.

All ledgers are monkeypatched to temp JSONL files; production ledgers are NEVER
touched. The builder is read-only, so these tests also assert the ledgers are
unchanged after building, and that no current-clock field (``generated_at``)
appears in any output. Verdicts are asserted to be copied VERBATIM (never
inferred).
"""

from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import attest_service as svc  # noqa: E402
import sar402_recording_store as recording_store  # noqa: E402
import chain_correlation as cc  # noqa: E402

CONT_A = "sha256:" + "a" * 64
SAR_A = "b" * 64  # SAR receipt id stored as a bare 64-hex hash (chain convention)
CHAIN_A = "sha256:" + "c" * 64  # chain WITH sar_verdict + a recording wrapper

CONT_B = "sha256:" + "d" * 64
SAR_B = "e" * 64
CHAIN_B = "sha256:" + "f" * 64  # chain with NO wrapper on its SAR receipt

# A wrapped-but-unchained SAR receipt (sha256:-prefixed, like the real one).
SAR_LONE = "sha256:" + "1" * 64

UNKNOWN_CHAIN = "sha256:" + "9" * 64


def _chain(chain_id, cont_id, sar_id, sar_verdict=None):
    return {
        "chain_id": chain_id,
        "agent_id": "agent:test",
        "activation_id": None,
        "continuity_receipt_id": cont_id,
        "sar_receipt_id": sar_id,
        "time_delta_seconds": None,
        "continuity_classification": None,
        "sar_verdict": sar_verdict,
        "verdict_correlation": None,
        "predicate_status_vector": None,
        "stage": "chained",
        "receipt_context": "real_task",
        "created_at": "2026-06-30T00:00:00Z",
    }


def _receipt_record(receipt_id, receipt_type):
    return {
        "receipt_id": receipt_id,
        "receipt_type": receipt_type,
        "receipt_context": "real_task",
        "agent_id": None,
        "activation_id": None,
        "chain_id": None,
        "created_at": "2026-06-30T00:00:00Z",
        "receipt": {"receipt_id": receipt_id},
    }


def _wrapper(wrapped_receipt_id):
    return {
        "wrapper_type": "sar402_recording_wrapper",
        "wrapper_version": "sar402_recording_wrapper_v1",
        "recording_context": "sar_402_settlement",
        "wrapped_receipt_id": wrapped_receipt_id,
        "wrapped_receipt_digest": "sha256:" + "0" * 64,
        "recording_key_id": "recording-key-test",
        "recording_signature": {"alg": "ed25519", "signature": "SIG"},
        "authority_boundary": {
            "signature_attests_to": "recording_attribution_only",
            "verifier_has_execution_authority": False,
        },
    }


def _write_jsonl(path, records):
    with open(path, "w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, separators=(",", ":")) + "\n")


@pytest.fixture
def ledgers(tmp_path, monkeypatch):
    chain_path = tmp_path / "chains.jsonl"
    receipt_path = tmp_path / "receipts.jsonl"
    wrapper_path = tmp_path / "wrappers.jsonl"

    _write_jsonl(
        chain_path,
        [
            _chain(CHAIN_A, CONT_A, SAR_A, sar_verdict="PASS"),
            _chain(CHAIN_B, CONT_B, SAR_B, sar_verdict=None),
        ],
    )
    _write_jsonl(
        receipt_path,
        [
            _receipt_record(CONT_A, "continuity"),
            _receipt_record(SAR_A, "sar_402_settlement"),
            _receipt_record(CONT_B, "continuity"),
            _receipt_record(SAR_B, "sar_402_settlement"),
            _receipt_record(SAR_LONE, "sar_402_settlement"),
        ],
    )
    # Wrapper only for SAR_A and the lone (unchained) SAR receipt.
    _write_jsonl(wrapper_path, [_wrapper(SAR_A), _wrapper(SAR_LONE)])

    monkeypatch.setattr(svc, "CHAIN_LEDGER", chain_path)
    monkeypatch.setattr(svc, "RECEIPT_LEDGER", receipt_path)
    monkeypatch.setattr(recording_store, "RECORDING_WRAPPER_LEDGER", wrapper_path)
    # Recording wrapper verifies (stub the verified-wrapper path deterministically).
    monkeypatch.setattr(svc, "_recording_public_key", lambda: "PUBKEY")
    monkeypatch.setattr(svc, "verify_recording_wrapper", lambda w, public_key: True)
    return chain_path, receipt_path, wrapper_path


# ---------------------------------------------------------------------------
# Acceptance test 1 — populated verdict chain, verbatim verdicts
# ---------------------------------------------------------------------------

def test_chain_with_populated_sar_verdict(ledgers):
    view = cc.build_correlation(chain_id=CHAIN_A)
    assert view["correlation_schema"] == "ds.chain_correlation.v0.1"
    assert view["status"] == "resolved"
    assert view["chain_id"] == CHAIN_A
    roles = {r["role"]: r for r in view["receipts"]}
    assert roles["continuity"]["receipt_id"] == CONT_A
    assert roles["sar"]["receipt_id"] == SAR_A
    # Verdicts copied VERBATIM; only sar_verdict populated, others null (not inferred).
    assert view["verdicts"] == {
        "sar_verdict": "PASS",
        "continuity_classification": None,
        "verdict_correlation": None,
    }
    types = {e["type"] for e in view["relationships"]}
    assert {"continuity_to_sar", "sar_to_chain", "chain_to_verdict"} <= types


# ---------------------------------------------------------------------------
# Acceptance test 2 — wrapped, unchained receipt: wrapper verbatim, chain absent
# ---------------------------------------------------------------------------

def test_wrapped_unchained_receipt(ledgers):
    view = cc.build_correlation(receipt_id=SAR_LONE)
    assert view["status"] == "resolved"
    assert view["chain_id"] is None
    assert view["recording_wrapper"]["status"] == "present_verified"
    # authority_boundary copied verbatim from the stored wrapper.
    assert view["recording_wrapper"]["authority_boundary_summary"] == {
        "signature_attests_to": "recording_attribution_only",
        "verifier_has_execution_authority": False,
    }
    # No fabricated chain / verdicts / counterpart receipt.
    assert view["verdicts"]["sar_verdict"] is None
    assert len(view["receipts"]) == 1
    assert "no chain record references this receipt" in view["notes"]


# ---------------------------------------------------------------------------
# Acceptance test 3 — chained SAR receipt with no wrapper -> absent, no error
# ---------------------------------------------------------------------------

def test_chained_sar_receipt_without_wrapper(ledgers):
    view = cc.build_correlation(chain_id=CHAIN_B)
    assert view["status"] == "resolved"
    assert view["recording_wrapper"]["status"] == "absent"
    assert view["recording_wrapper"]["authority_boundary_summary"] is None


# ---------------------------------------------------------------------------
# Acceptance test 4 — unknown chain_id -> structured not_found + non-zero CLI
# ---------------------------------------------------------------------------

def test_unknown_chain_id_not_found(ledgers, capsys):
    view = cc.build_correlation(chain_id=UNKNOWN_CHAIN)
    assert view["status"] == "not_found"
    assert view["receipts"] == []

    rc = cc.run(["--chain-id", UNKNOWN_CHAIN])
    assert rc == 1
    out = json.loads(capsys.readouterr().out)
    assert out["status"] == "not_found"


# ---------------------------------------------------------------------------
# Acceptance test 5 — deterministic, no generated_at
# ---------------------------------------------------------------------------

def test_output_deterministic_and_no_clock_field(ledgers, capsys):
    out1 = json.dumps(cc.build_correlation(chain_id=CHAIN_A), sort_keys=True)
    out2 = json.dumps(cc.build_correlation(chain_id=CHAIN_A), sort_keys=True)
    assert out1 == out2
    assert "generated_at" not in out1

    rc = cc.run(["--chain-id", CHAIN_A])
    assert rc == 0
    captured = capsys.readouterr().out
    assert "generated_at" not in captured


# ---------------------------------------------------------------------------
# Acceptance test 6 — ledgers unchanged after all runs
# ---------------------------------------------------------------------------

def test_no_ledger_mutation_after_build(ledgers):
    chain_path, receipt_path, wrapper_path = ledgers
    before = {p: p.read_bytes() for p in (chain_path, receipt_path, wrapper_path)}
    cc.run(["--chain-id", CHAIN_A])
    cc.run(["--chain-id", CHAIN_B])
    cc.run(["--receipt-id", SAR_LONE])
    cc.run(["--receipt-id", SAR_A])
    cc.run(["--chain-id", UNKNOWN_CHAIN])
    after = {p: p.read_bytes() for p in (chain_path, receipt_path, wrapper_path)}
    assert before == after


# ---------------------------------------------------------------------------
# Acceptance test 7 — malformed ids and ambiguous selector raise / exit non-zero
# ---------------------------------------------------------------------------

def test_malformed_chain_id_raises(ledgers):
    with pytest.raises(ValueError):
        cc.build_correlation(chain_id="not-a-sha")


def test_malformed_receipt_id_raises(ledgers):
    with pytest.raises(ValueError):
        cc.build_correlation(receipt_id="xyz")


def test_ambiguous_or_missing_selector_raises(ledgers):
    with pytest.raises(ValueError):
        cc.build_correlation()
    with pytest.raises(ValueError):
        cc.build_correlation(chain_id=CHAIN_A, receipt_id=SAR_A)


def test_cli_malformed_chain_id_exit_code(ledgers):
    rc = cc.run(["--chain-id", "not-a-sha"])
    assert rc == 2


# ---------------------------------------------------------------------------
# Extra — resolve chain via --receipt-id (bare SAR hash)
# ---------------------------------------------------------------------------

def test_receipt_id_resolves_chain(ledgers):
    view = cc.build_correlation(receipt_id=SAR_A)
    assert view["status"] == "resolved"
    assert view["chain_id"] == CHAIN_A
    assert view["verdicts"]["sar_verdict"] == "PASS"
