"""Tests for the Phase 1 read-only Path C evidence graph extractor.

All ledgers are monkeypatched to temp JSONL files; production ledgers are NEVER
touched. The extractor is read-only, so these tests also assert the ledgers are
unchanged after extraction, and that no current-clock field (``generated_at``)
appears in any output.
"""

from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import action_commitment_store as acs  # noqa: E402
import continuity_evaluation_receipts as cer  # noqa: E402
import deterministic_evaluation_store as des  # noqa: E402
import evidence_graph_extractor as ege  # noqa: E402

REF_A = "sha256:" + "a" * 64  # full chain: commitment + eval(PASS) + receipt
REF_B = "sha256:" + "b" * 64  # commitment + eval(INDETERMINATE + reason) only
REF_C = "sha256:" + "c" * 64  # commitment only
EVALUATOR = "agent:defaultverifier:continuity-v1"


def _commitment(action_ref: str) -> dict:
    return {
        "record_type": "action_commitment_record",
        "record_version": "action_commitment_record_v1",
        "action_ref": action_ref,
        "action_commitment": {"schema_id": "ds.action_commitment.v0.1"},
    }


def _evaluation(action_ref: str, result: str, reason_code: str | None = None) -> dict:
    rec = {
        "record_type": "deterministic_evaluation_record",
        "record_version": "deterministic_evaluation_record_v1",
        "action_ref": action_ref,
        "result": result,
        "checks": [],
    }
    if reason_code is not None:
        rec["reason_code"] = reason_code
    return rec


def _receipt(action_ref: str, state: str) -> dict:
    return {
        "schema_id": "ds.continuity_evaluation.v0.1",
        "action_ref": action_ref,
        "evaluator_id": EVALUATOR,
        "evaluation_state": state,
        "policy_ref": "policy:test",
        "evaluated_at": "2026-06-27T00:00:00Z",
        "signature": {
            "alg": "ed25519",
            "key_id": EVALUATOR,
            "public_key": "PUBKEY",
            "signature": "SIG",
        },
    }


def _write_jsonl(path, records) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, separators=(",", ":")) + "\n")


@pytest.fixture
def ledgers(tmp_path, monkeypatch):
    commit_path = tmp_path / "commitments.jsonl"
    eval_path = tmp_path / "evals.jsonl"
    receipt_path = tmp_path / "receipts.jsonl"

    _write_jsonl(
        commit_path,
        [_commitment(REF_A), _commitment(REF_B), _commitment(REF_C)],
    )
    _write_jsonl(
        eval_path,
        [
            _evaluation(REF_A, "PASS"),
            _evaluation(REF_B, "INDETERMINATE", reason_code="MISSING_ACCEPTANCE_SPEC"),
        ],
    )
    _write_jsonl(receipt_path, [_receipt(REF_A, "PASS")])

    monkeypatch.setattr(acs, "ACTION_COMMITMENT_LEDGER", commit_path)
    monkeypatch.setattr(des, "DETERMINISTIC_EVALUATION_LEDGER", eval_path)
    monkeypatch.setattr(cer, "CONTINUITY_EVALUATION_RECEIPT_LEDGER", receipt_path)
    return commit_path, eval_path, receipt_path


def _node_ids(graph) -> set:
    return {n["node_id"] for n in graph["nodes"]}


def _edges_of(graph, edge_type) -> list:
    return [e for e in graph["edges"] if e["edge_type"] == edge_type]


# ---------------------------------------------------------------------------
# Full graph
# ---------------------------------------------------------------------------

def test_full_graph_from_three_populated_ledgers(ledgers):
    graph = ege.build_graph(ege.resolve_action_refs())
    assert graph["graph_schema"] == "ds.evidence_graph.v0.1"
    ids = _node_ids(graph)
    # All three artifact node types present.
    assert f"action_commitment:{REF_A}" in ids
    assert f"deterministic_evaluation_record:{REF_A}" in ids
    assert f"continuity_evaluation_receipt:{REF_A}" in ids
    # Value nodes.
    assert f"action_ref:{REF_A}" in ids
    assert f"evaluator_identity:{EVALUATOR}" in ids
    assert "reason_code:MISSING_ACCEPTANCE_SPEC" in ids


# ---------------------------------------------------------------------------
# Filters
# ---------------------------------------------------------------------------

def test_subgraph_by_action_ref(ledgers):
    graph = ege.build_graph(ege.resolve_action_refs(action_ref=REF_A))
    for node in graph["nodes"]:
        if node["node_type"] in (
            "action_commitment",
            "deterministic_evaluation_record",
            "continuity_evaluation_receipt",
        ):
            assert node["action_ref"] == REF_A
    assert f"action_commitment:{REF_B}" not in _node_ids(graph)


def test_subgraph_by_evaluator(ledgers):
    graph = ege.build_graph(ege.resolve_action_refs(evaluator=EVALUATOR))
    ids = _node_ids(graph)
    # Only REF_A has a signed receipt -> its chain is included.
    assert f"continuity_evaluation_receipt:{REF_A}" in ids
    assert f"deterministic_evaluation_record:{REF_A}" in ids
    assert f"action_commitment:{REF_A}" in ids
    assert f"action_commitment:{REF_B}" not in ids


def test_subgraph_by_reason_code(ledgers):
    graph = ege.build_graph(
        ege.resolve_action_refs(reason_code="MISSING_ACCEPTANCE_SPEC")
    )
    ids = _node_ids(graph)
    assert f"deterministic_evaluation_record:{REF_B}" in ids
    assert f"action_commitment:{REF_B}" in ids
    assert "reason_code:MISSING_ACCEPTANCE_SPEC" in ids
    assert f"action_commitment:{REF_A}" not in ids


def test_valid_filter_no_match_returns_empty_graph(ledgers):
    empty_ref = "sha256:" + "f" * 64
    graph = ege.build_graph(ege.resolve_action_refs(action_ref=empty_ref))
    assert graph == {
        "graph_schema": "ds.evidence_graph.v0.1",
        "nodes": [],
        "edges": [],
    }


def test_invalid_action_ref_filter_raises(ledgers):
    with pytest.raises(ValueError):
        ege.resolve_action_refs(action_ref="not-a-sha")


def test_invalid_evaluator_filter_raises(ledgers):
    with pytest.raises(ValueError):
        ege.resolve_action_refs(evaluator="NOT_AN_AGENT_ID")


def test_invalid_filter_cli_exit_code(ledgers):
    rc = ege.run(["--action-ref", "not-a-sha"])
    assert rc != 0


# ---------------------------------------------------------------------------
# Edge derivation rules
# ---------------------------------------------------------------------------

def test_action_ref_with_no_evaluation_has_no_evaluates_edge(ledgers):
    graph = ege.build_graph(ege.resolve_action_refs(action_ref=REF_C))
    assert f"action_commitment:{REF_C}" in _node_ids(graph)
    assert _edges_of(graph, "evaluates") == []


def test_action_ref_with_eval_but_no_receipt_is_partial_chain(ledgers):
    graph = ege.build_graph(ege.resolve_action_refs(action_ref=REF_B))
    ids = _node_ids(graph)
    assert f"deterministic_evaluation_record:{REF_B}" in ids
    assert f"continuity_evaluation_receipt:{REF_B}" not in ids
    # evaluates edge present (eval + commitment), attests_evaluation absent.
    assert len(_edges_of(graph, "evaluates")) == 1
    assert _edges_of(graph, "attests_evaluation") == []


def test_indeterminate_with_reason_code_emits_has_reason_code_edge(ledgers):
    graph = ege.build_graph(ege.resolve_action_refs(action_ref=REF_B))
    edges = _edges_of(graph, "has_reason_code")
    assert len(edges) == 1
    assert edges[0]["to"] == "reason_code:MISSING_ACCEPTANCE_SPEC"


def test_pass_with_no_reason_code_has_no_has_reason_code_edge(ledgers):
    graph = ege.build_graph(ege.resolve_action_refs(action_ref=REF_A))
    assert _edges_of(graph, "has_reason_code") == []


# ---------------------------------------------------------------------------
# Determinism / value node ids / no dangling targets
# ---------------------------------------------------------------------------

def test_value_node_ids_are_deterministic(ledgers):
    g1 = ege.build_graph(ege.resolve_action_refs())
    g2 = ege.build_graph(ege.resolve_action_refs())
    value_ids_1 = sorted(
        n["node_id"] for n in g1["nodes"] if "value" in n
    )
    value_ids_2 = sorted(
        n["node_id"] for n in g2["nodes"] if "value" in n
    )
    assert value_ids_1 == value_ids_2
    assert f"action_ref:{REF_A}" in value_ids_1


def test_no_dangling_edge_targets(ledgers):
    graph = ege.build_graph(ege.resolve_action_refs())
    ids = _node_ids(graph)
    for edge in graph["edges"]:
        assert edge["from"] in ids
        assert edge["to"] in ids


def test_output_is_deterministic_across_runs(ledgers):
    out1 = json.dumps(ege.build_graph(ege.resolve_action_refs()), sort_keys=True)
    out2 = json.dumps(ege.build_graph(ege.resolve_action_refs()), sort_keys=True)
    assert out1 == out2


def test_no_generated_at_or_clock_fields(ledgers, capsys):
    rc = ege.run([])
    assert rc == 0
    captured = capsys.readouterr().out
    assert "generated_at" not in captured
    graph = json.loads(captured)
    assert "generated_at" not in graph
    for node in graph["nodes"]:
        assert "generated_at" not in node


def test_no_ledger_mutation_after_run(ledgers):
    commit_path, eval_path, receipt_path = ledgers
    before = {p: p.read_bytes() for p in (commit_path, eval_path, receipt_path)}
    ege.run([])
    ege.run(["--action-ref", REF_A])
    ege.run(["--evaluator", EVALUATOR])
    ege.run(["--reason-code", "MISSING_ACCEPTANCE_SPEC"])
    after = {p: p.read_bytes() for p in (commit_path, eval_path, receipt_path)}
    assert before == after
