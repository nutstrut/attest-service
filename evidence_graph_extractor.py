"""Evidence Graph Phase 1 — read-only, deterministic Path C graph extractor.

This CLI reads the three immutable Path C JSONL ledgers and emits a
deterministic JSON graph view to stdout. It is strictly read-only:

    * It NEVER writes to, mutates, or re-orders any ledger.
    * It does NOT verify signatures, authorize, execute, release, or settle.
    * It does NOT compute freshness, expiry, revocation, key validity, or
      current acceptability. There is no STALE / REVOKED / UNKNOWN_KEY /
      MISSING_STATUS / POLICY_VERSION_MISMATCH vocabulary here (those are
      explicit NON-GOALS of Phase 1 and are deliberately absent from the
      implementation logic below).

Edge presence proves only that the named relationship exists between indexed
artifacts. No edge is stored; every edge is derived. No edge adds authority.

The output is structurally deterministic / byte-stable across repeated runs over
the same ledger state: nodes and edges are sorted by stable keys and no field is
derived from the current clock (there is no ``generated_at``).

Source ledgers (read only, via each store's own JSONL read helper + ledger
path constant, so tests can monkeypatch temp ledgers):

    attest_action_commitments_master.jsonl       (action_commitment_store)
    attest_deterministic_evaluations_master.jsonl(deterministic_evaluation_store)
    attest_continuity_evaluation_receipts_master.jsonl (continuity_evaluation_receipts)
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Optional

import action_commitment_store as acs
import continuity_evaluation_receipts as cer
import deterministic_evaluation_store as des

GRAPH_SCHEMA = "ds.evidence_graph.v0.1"

# Artifact node types.
NODE_ACTION_COMMITMENT = "action_commitment"
NODE_DETERMINISTIC_EVALUATION = "deterministic_evaluation_record"
NODE_CONTINUITY_RECEIPT = "continuity_evaluation_receipt"

# Value node types.
VALUE_ACTION_REF = "action_ref"
VALUE_EVALUATOR_IDENTITY = "evaluator_identity"
VALUE_REASON_CODE = "reason_code"


# ---------------------------------------------------------------------------
# Read-only ledger access (latest record per action_ref, mirroring the stores)
# ---------------------------------------------------------------------------

def _latest_by_action_ref(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Collapse an append-only ledger to the latest record per ``action_ref``.

    Mirrors the single-active-record semantics of the stores' ``get_*`` helpers
    (last matching record wins). Read-only; the ledger is never mutated."""
    out: dict[str, dict[str, Any]] = {}
    for record in records:
        ref = record.get("action_ref")
        if isinstance(ref, str) and ref:
            out[ref] = record
    return out


def _load_ledgers() -> tuple[
    dict[str, dict[str, Any]],
    dict[str, dict[str, Any]],
    dict[str, dict[str, Any]],
]:
    """Load the three Path C ledgers, latest-per-action_ref. Read-only.

    Ledger path constants are resolved at call time so tests monkeypatching the
    store module ledger constants take effect."""
    commitments = _latest_by_action_ref(acs._read_jsonl(acs.ACTION_COMMITMENT_LEDGER))
    evaluations = _latest_by_action_ref(
        des._read_jsonl(des.DETERMINISTIC_EVALUATION_LEDGER)
    )
    receipts = _latest_by_action_ref(
        cer._read_jsonl(cer.CONTINUITY_EVALUATION_RECEIPT_LEDGER)
    )
    return commitments, evaluations, receipts


# ---------------------------------------------------------------------------
# Node id conventions (deterministic; stable across runs)
# ---------------------------------------------------------------------------

def _artifact_node_id(node_type: str, action_ref: str) -> str:
    return f"{node_type}:{action_ref}"


def _value_node_id(node_type: str, value: str) -> str:
    return f"{node_type}:{value}"


# ---------------------------------------------------------------------------
# Artifact node builders. Fields that do not apply to a node type are ``null``.
# evaluation_state / reason_code are read from stored records, never inferred.
# ---------------------------------------------------------------------------

def _commitment_node(action_ref: str, record: dict[str, Any]) -> dict[str, Any]:
    ac = record.get("action_commitment")
    schema_id = ac.get("schema_id") if isinstance(ac, dict) else None
    return {
        "node_id": _artifact_node_id(NODE_ACTION_COMMITMENT, action_ref),
        "node_type": NODE_ACTION_COMMITMENT,
        "action_ref": action_ref,
        "schema_id": schema_id,
        "evaluation_state": None,
        "reason_code": None,
        "evaluator_id": None,
        "evaluated_at": None,
        "has_signature": False,
    }


def _evaluation_node(action_ref: str, record: dict[str, Any]) -> dict[str, Any]:
    return {
        "node_id": _artifact_node_id(NODE_DETERMINISTIC_EVALUATION, action_ref),
        "node_type": NODE_DETERMINISTIC_EVALUATION,
        "action_ref": action_ref,
        "schema_id": record.get("schema_id"),
        # Read verbatim from the stored record; not inferred.
        "evaluation_state": record.get("result"),
        "reason_code": record.get("reason_code"),
        "evaluator_id": None,
        "evaluated_at": None,
        "has_signature": False,
    }


def _receipt_node(action_ref: str, record: dict[str, Any]) -> dict[str, Any]:
    has_signature = isinstance(record.get("signature"), dict)
    return {
        "node_id": _artifact_node_id(NODE_CONTINUITY_RECEIPT, action_ref),
        "node_type": NODE_CONTINUITY_RECEIPT,
        "action_ref": action_ref,
        "schema_id": record.get("schema_id"),
        "evaluation_state": record.get("evaluation_state"),
        "reason_code": record.get("reason_code"),
        "evaluator_id": record.get("evaluator_id"),
        "evaluated_at": record.get("evaluated_at"),
        "has_signature": has_signature,
    }


def _value_node(node_type: str, value: str) -> dict[str, Any]:
    return {
        "node_id": _value_node_id(node_type, value),
        "node_type": node_type,
        "value": value,
    }


# ---------------------------------------------------------------------------
# Graph construction. All edges are derived deterministically (no inference).
# ---------------------------------------------------------------------------

def build_graph(action_refs: list[str]) -> dict[str, Any]:
    """Build the deterministic graph view for the given ``action_refs``.

    ``action_refs`` is the already-resolved set of refs to include (the full
    ledger union, or a filtered subset). Every edge's ``from``/``to`` is added
    to ``nodes`` so there are no dangling edge targets."""
    commitments, evaluations, receipts = _load_ledgers()

    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []

    def add_node(node: dict[str, Any]) -> None:
        nodes.setdefault(node["node_id"], node)

    def add_edge(edge_type: str, src: str, dst: str) -> None:
        edges.append(
            {"edge_type": edge_type, "from": src, "to": dst, "derived": True}
        )

    for action_ref in action_refs:
        commitment = commitments.get(action_ref)
        evaluation = evaluations.get(action_ref)
        receipt = receipts.get(action_ref)

        commit_id = _artifact_node_id(NODE_ACTION_COMMITMENT, action_ref)
        eval_id = _artifact_node_id(NODE_DETERMINISTIC_EVALUATION, action_ref)
        receipt_id = _artifact_node_id(NODE_CONTINUITY_RECEIPT, action_ref)

        # --- Action Commitment node + self-referential action_ref value edge ---
        if commitment is not None:
            add_node(_commitment_node(action_ref, commitment))
            # references: Action Commitment --references--> action_ref value node
            # (always derived for each Action Commitment).
            value_id = _value_node_id(VALUE_ACTION_REF, action_ref)
            add_node(_value_node(VALUE_ACTION_REF, action_ref))
            add_edge("references", commit_id, value_id)

        # --- Deterministic Evaluation Record node ---
        if evaluation is not None:
            add_node(_evaluation_node(action_ref, evaluation))
            # evaluates: Deterministic Evaluation Record --> Action Commitment,
            # derived only when a matching action_ref exists in both ledgers.
            if commitment is not None:
                add_edge("evaluates", eval_id, commit_id)
            # has_reason_code: only when reason_code is non-null on the record.
            reason_code = evaluation.get("reason_code")
            if reason_code is not None:
                value_id = _value_node_id(VALUE_REASON_CODE, reason_code)
                add_node(_value_node(VALUE_REASON_CODE, reason_code))
                add_edge("has_reason_code", eval_id, value_id)

        # --- Continuity Evaluation Receipt node ---
        if receipt is not None:
            add_node(_receipt_node(action_ref, receipt))
            # attests_evaluation: Receipt --> Deterministic Evaluation Record,
            # derived only when a matching action_ref exists in both ledgers.
            if evaluation is not None:
                add_edge("attests_evaluation", receipt_id, eval_id)
            # signed_by: Receipt --> evaluator_identity value node, derived from
            # signature.key_id present on the signed receipt. No key validity,
            # freshness, or revocation is resolved here.
            signature = receipt.get("signature")
            if isinstance(signature, dict):
                key_id = signature.get("key_id")
                if isinstance(key_id, str) and key_id:
                    value_id = _value_node_id(VALUE_EVALUATOR_IDENTITY, key_id)
                    add_node(_value_node(VALUE_EVALUATOR_IDENTITY, key_id))
                    add_edge("signed_by", receipt_id, value_id)

    sorted_nodes = sorted(nodes.values(), key=lambda n: n["node_id"])
    sorted_edges = sorted(
        edges, key=lambda e: (e["edge_type"], e["from"], e["to"])
    )
    return {
        "graph_schema": GRAPH_SCHEMA,
        "nodes": sorted_nodes,
        "edges": sorted_edges,
    }


# ---------------------------------------------------------------------------
# Filter resolution: each filter resolves to a set of action_refs.
# ---------------------------------------------------------------------------

def _all_action_refs() -> list[str]:
    commitments, evaluations, receipts = _load_ledgers()
    refs = set(commitments) | set(evaluations) | set(receipts)
    return sorted(refs)


def resolve_action_refs(
    *,
    action_ref: Optional[str] = None,
    evaluator: Optional[str] = None,
    reason_code: Optional[str] = None,
) -> list[str]:
    """Resolve the selected filter to a deterministic, sorted list of action_refs.

    Raises ``ValueError`` for a structurally invalid filter value. A valid
    filter that simply matches no records returns an empty list (-> empty
    graph)."""
    if action_ref is not None:
        if not des.is_valid_action_ref(action_ref):
            raise ValueError(
                f"--action-ref must be of the form sha256:<64 hex>; got {action_ref!r}"
            )
        commitments, evaluations, receipts = _load_ledgers()
        if action_ref in commitments or action_ref in evaluations or action_ref in receipts:
            return [action_ref]
        return []

    if evaluator is not None:
        if not cer._is_valid_evaluator_id(evaluator):
            raise ValueError(
                "--evaluator must use the agent: identity scheme; "
                f"got {evaluator!r}"
            )
        _, _, receipts = _load_ledgers()
        refs = set()
        for ref, receipt in receipts.items():
            signature = receipt.get("signature")
            if isinstance(signature, dict) and signature.get("key_id") == evaluator:
                refs.add(ref)
        return sorted(refs)

    if reason_code is not None:
        if not isinstance(reason_code, str) or not reason_code:
            raise ValueError("--reason-code must be a non-empty string")
        _, evaluations, _ = _load_ledgers()
        refs = {
            ref
            for ref, record in evaluations.items()
            if record.get("reason_code") == reason_code
        }
        return sorted(refs)

    # No filter: full graph over the union of all three ledgers.
    return _all_action_refs()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="evidence_graph_extractor.py",
        description=(
            "Read-only, deterministic Path C evidence graph extractor "
            "(Phase 1). Emits a JSON graph view to stdout. It does NOT verify, "
            "authorize, execute, release, settle, or compute current "
            "acceptability."
        ),
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--action-ref", help="Emit the subgraph for this action_ref only.")
    group.add_argument(
        "--evaluator",
        help="Emit receipts signed by this evaluator identity (plus related nodes).",
    )
    group.add_argument(
        "--reason-code",
        help="Emit evaluations with this reason_code (plus related nodes).",
    )
    return parser


def run(argv: Optional[list[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        action_refs = resolve_action_refs(
            action_ref=args.action_ref,
            evaluator=args.evaluator,
            reason_code=args.reason_code,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    graph = build_graph(action_refs)
    # Deterministic serialization: sorted keys, stable indentation, no clock.
    print(json.dumps(graph, indent=2, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(run())
