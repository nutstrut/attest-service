"""Tests that attest-service accepts and preserves delegated-identity fields
(executor_id / execution_mode) without changing chain-id derivation, agent_id
attribution, or existing historical record shape.

CHAIN_LEDGER is monkeypatched to a temp file; the production ledger is never
touched.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import attest_service as svc  # noqa: E402

MORPHEUS_AGENT_ID = "agent:morpheus"
HERMES_EXECUTOR_ID = "0xf23C8C0695e0Bd7c6eB979AEc128386Bf1ce3dCc:hermes"


def test_write_chain_preserves_executor_id_and_execution_mode(tmp_path, monkeypatch):
    chain_path = tmp_path / "attest_chains_master.jsonl"
    monkeypatch.setattr(svc, "CHAIN_LEDGER", chain_path)

    record = svc.write_chain(
        chain_id="sha256:" + "a" * 64,
        agent_id=MORPHEUS_AGENT_ID,
        activation_id=None,
        continuity_receipt_id="sha256:" + "b" * 64,
        sar_receipt_id="c" * 64,
        stage="chained",
        receipt_context="real_task",
        executor_id=HERMES_EXECUTOR_ID,
        execution_mode="delegated",
    )

    assert record["agent_id"] == MORPHEUS_AGENT_ID
    assert record["executor_id"] == HERMES_EXECUTOR_ID
    assert record["execution_mode"] == "delegated"

    with open(chain_path) as f:
        stored = json.loads(f.readline())
    assert stored["executor_id"] == HERMES_EXECUTOR_ID
    assert stored["execution_mode"] == "delegated"


def test_write_chain_without_new_fields_is_legacy_shaped(tmp_path, monkeypatch):
    chain_path = tmp_path / "attest_chains_master.jsonl"
    monkeypatch.setattr(svc, "CHAIN_LEDGER", chain_path)

    record = svc.write_chain(
        chain_id="sha256:" + "a" * 64,
        agent_id=MORPHEUS_AGENT_ID,
        activation_id=None,
        continuity_receipt_id="sha256:" + "b" * 64,
        sar_receipt_id="c" * 64,
        stage="chained",
        receipt_context="real_task",
    )

    assert "executor_id" not in record
    assert "execution_mode" not in record


def test_sync_attest_input_sar_input_is_a_free_form_dict():
    # sar_input is typed dict[str, Any]: attest-service does not need a schema
    # change to accept/forward executor_id and execution_mode. This test pins
    # that behavior so a future, more restrictive model change would be caught.
    payload = svc.SyncAttestInput(
        continuity_input={},
        sar_input={
            "task_id": "t1",
            "agent_id": MORPHEUS_AGENT_ID,
            "executor_id": HERMES_EXECUTOR_ID,
            "execution_mode": "delegated",
        },
    )
    assert payload.sar_input["executor_id"] == HERMES_EXECUTOR_ID
    assert payload.sar_input["execution_mode"] == "delegated"


def test_attest_handler_forwards_executor_id_to_write_chain(tmp_path, monkeypatch):
    chain_path = tmp_path / "attest_chains_master.jsonl"
    receipt_path = tmp_path / "attest_receipts_master.jsonl"
    monkeypatch.setattr(svc, "CHAIN_LEDGER", chain_path)
    monkeypatch.setattr(svc, "RECEIPT_LEDGER", receipt_path)

    def fake_post_json(url, payload):
        if url == svc.CONTINUITY_EVALUATE_URL:
            return {"receipt_id": "sha256:" + "1" * 64}
        if url == svc.SAR_URL:
            # Echo enough of the real settlement-witness response shape.
            return {
                "receipt_id": "sha256:" + "2" * 64,
                "receipt_v0_1": {"verdict": "PASS"},
                "_ext": {
                    "agent_id": payload.get("agent_id"),
                    "executor_id": payload.get("executor_id"),
                    "execution_mode": payload.get("execution_mode"),
                },
            }
        raise AssertionError(f"unexpected post_json url: {url}")

    monkeypatch.setattr(svc, "post_json", fake_post_json)

    input_model = svc.SyncAttestInput(
        continuity_input={},
        sar_input={
            "task_id": "hermes-verify-sar-spec-v1",
            "agent_id": MORPHEUS_AGENT_ID,
            "executor_id": HERMES_EXECUTOR_ID,
            "execution_mode": "delegated",
        },
    )

    result = svc.attest(input_model)

    assert result["sar"]["_ext"]["agent_id"] == MORPHEUS_AGENT_ID
    assert result["sar"]["_ext"]["executor_id"] == HERMES_EXECUTOR_ID
    assert result["sar"]["_ext"]["execution_mode"] == "delegated"

    with open(chain_path) as f:
        stored_chain = json.loads(f.readline())

    assert stored_chain["agent_id"] == MORPHEUS_AGENT_ID
    assert stored_chain["executor_id"] == HERMES_EXECUTOR_ID
    assert stored_chain["execution_mode"] == "delegated"
