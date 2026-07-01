"""Evidence Graph Phase 2 — read-only chain correlation view.

This module assembles a single, machine-readable correlation view for one
evidence chain, answering exactly one question:

    Can the system show that a Continuity receipt, a SAR-402 receipt, a
    chain_id, and a verdict belong to the same evidence chain, and explain how
    they relate?

It is strictly read-only and does exactly one thing — *assemble* what already
exists across three ledgers into one correlated shape:

    attest_chains_master.jsonl            (the chain spine: chain_id +
                                           continuity_receipt_id + sar_receipt_id
                                           + sar_verdict + ...)
    attest_receipts_master.jsonl          (receipt presence / receipt_type)
    attest_recording_wrappers_master.jsonl(Path B recording attribution wrapper)

Doctrine (non-negotiable), mirroring the Phase 1 extractor:

    * It NEVER writes to, mutates, re-orders, or creates any ledger.
    * It does NOT execute, authorize, release, settle, or custody anything.
    * It does NOT INFER verdicts. ``sar_verdict``, ``continuity_classification``
      and ``verdict_correlation`` are copied VERBATIM from the stored chain
      record; when absent they are emitted as ``null``. There is no vocabulary
      here that computes, backfills, or correlates a verdict.
    * It does NOT merge Path A / Path B / Path C id spaces or semantics. Receipt
      roles stay explicit; a wrapped-but-unchained receipt and a chained-but-
      unwrapped SAR receipt both render truthfully.
    * The recording wrapper is reported through the SAME verified-wrapper path
      the live endpoint uses — an unverifiable stored wrapper is reported as
      such, never served as valid.

The output is structurally deterministic / byte-stable across repeated runs
over the same ledger state: keys are sorted and no field is derived from the
current clock (there is no ``generated_at``).

All ledger access goes through ``attest_service`` helpers so tests that
monkeypatch the ledger path constants (and ``_recording_public_key``) take
effect and production storage is never touched.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Optional

import attest_service as svc

CORRELATION_SCHEMA = "ds.chain_correlation.v0.1"

# Static doctrine statement. DefaultVerifier records evidence; it does not
# execute the resource-server action, control delivery/release, or custody funds.
AUTHORITY_BOUNDARY_SUMMARY = (
    "DefaultVerifier records evidence; it does not execute the action, "
    "authorize or control resource release, or custody or move funds."
)

# Recording-wrapper status vocabulary (Path B). "absent" = no wrapper stored;
# "key_unavailable" = wrapper stored but no verification key configured;
# "present_verified" / "present_unverifiable" = wrapper verified or failed the
# same verification the live endpoint applies.
WRAPPER_ABSENT = "absent"
WRAPPER_KEY_UNAVAILABLE = "key_unavailable"
WRAPPER_PRESENT_VERIFIED = "present_verified"
WRAPPER_PRESENT_UNVERIFIABLE = "present_unverifiable"

STATUS_RESOLVED = "resolved"
STATUS_NOT_FOUND = "not_found"


# ---------------------------------------------------------------------------
# Id validation. chain_id is a sha256:<64 hex> id. A receipt id may be the
# sha256:-prefixed form (recording wrappers / continuity receipts) OR a bare
# 64-hex content hash (the SAR receipt id as stored in chain records). We accept
# both for --receipt-id and do NOT rewrite between the two forms (no id-space
# merging): each is matched verbatim against the ledger.
# ---------------------------------------------------------------------------

def _is_hex64(value: str) -> bool:
    return len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _is_valid_chain_id(chain_id: str) -> bool:
    return (
        isinstance(chain_id, str)
        and chain_id.startswith("sha256:")
        and _is_hex64(chain_id[len("sha256:"):])
    )


def _is_valid_receipt_id(receipt_id: str) -> bool:
    if not isinstance(receipt_id, str):
        return False
    if receipt_id.startswith("sha256:"):
        return _is_hex64(receipt_id[len("sha256:"):])
    return _is_hex64(receipt_id)


# ---------------------------------------------------------------------------
# Read-only resolution helpers
# ---------------------------------------------------------------------------

def _chain_for_receipt(receipt_id: str) -> Optional[dict[str, Any]]:
    """Return the latest chain record referencing ``receipt_id`` (as continuity
    or SAR receipt), or None. Read-only; matched verbatim, no id rewriting."""
    latest: Optional[dict[str, Any]] = None
    for record in svc.read_jsonl(svc.CHAIN_LEDGER):
        if (
            record.get("continuity_receipt_id") == receipt_id
            or record.get("sar_receipt_id") == receipt_id
        ):
            latest = record
    return latest


def _receipt_node(role: str, receipt_id: Optional[str]) -> dict[str, Any]:
    """Build a receipt node. ``present_in_ledger``/``receipt_type`` are read from
    the stored receipt record; never inferred. A null id yields an absent node."""
    if not receipt_id:
        return {
            "role": role,
            "receipt_id": None,
            "present_in_ledger": False,
            "receipt_type": None,
        }
    record = svc.find_receipt(receipt_id)
    return {
        "role": role,
        "receipt_id": receipt_id,
        "present_in_ledger": record is not None,
        "receipt_type": record.get("receipt_type") if record else None,
    }


def _recording_wrapper_view(sar_receipt_id: Optional[str]) -> dict[str, Any]:
    """Report Path B recording-wrapper status for a SAR receipt id, verbatim.

    Uses the same verified-wrapper path as the live endpoint: an unverifiable
    stored wrapper is reported as ``present_unverifiable``, never as valid. The
    authority_boundary is copied verbatim from the stored wrapper (not
    paraphrased) and this view adds no delivery/release/settlement claim."""
    if not sar_receipt_id:
        return {
            "status": WRAPPER_ABSENT,
            "wrapped_receipt_id": None,
            "authority_boundary_summary": None,
        }

    wrapper = svc.recording_store.get_recording_wrapper(sar_receipt_id)
    if wrapper is None:
        return {
            "status": WRAPPER_ABSENT,
            "wrapped_receipt_id": None,
            "authority_boundary_summary": None,
        }

    authority_boundary = wrapper.get("authority_boundary")
    public_key = svc._recording_public_key()
    if public_key is None:
        status = WRAPPER_KEY_UNAVAILABLE
    else:
        try:
            verified = svc.verify_recording_wrapper(wrapper, public_key=public_key)
        except Exception:  # pragma: no cover - defensive: never serve as valid
            verified = False
        status = WRAPPER_PRESENT_VERIFIED if verified else WRAPPER_PRESENT_UNVERIFIABLE

    return {
        "status": status,
        "wrapped_receipt_id": wrapper.get("wrapped_receipt_id"),
        # Copied verbatim from the stored wrapper; not paraphrased or narrowed.
        "authority_boundary_summary": authority_boundary,
    }


# ---------------------------------------------------------------------------
# Pure builder
# ---------------------------------------------------------------------------

def _not_found(chain_id: Optional[str], receipt_id: Optional[str]) -> dict[str, Any]:
    return {
        "correlation_schema": CORRELATION_SCHEMA,
        "status": STATUS_NOT_FOUND,
        "chain_id": chain_id,
        "receipt_id": receipt_id,
        "receipts": [],
        "verdicts": {
            "sar_verdict": None,
            "continuity_classification": None,
            "verdict_correlation": None,
        },
        "recording_wrapper": {
            "status": WRAPPER_ABSENT,
            "wrapped_receipt_id": None,
            "authority_boundary_summary": None,
        },
        "authority_boundary_summary": AUTHORITY_BOUNDARY_SUMMARY,
        "relationships": [],
        "notes": ["no chain or receipt found for the requested id"],
    }


def _build_from_chain(chain: dict[str, Any]) -> dict[str, Any]:
    """Assemble the correlation view from a resolved chain record. Read-only."""
    chain_id = chain.get("chain_id")
    continuity_id = chain.get("continuity_receipt_id")
    sar_id = chain.get("sar_receipt_id")

    continuity_node = _receipt_node("continuity", continuity_id)
    sar_node = _receipt_node("sar", sar_id)
    receipts = [continuity_node, sar_node]

    # Verdicts: copied VERBATIM from the stored chain record. Never inferred.
    sar_verdict = chain.get("sar_verdict")
    continuity_classification = chain.get("continuity_classification")
    verdict_correlation = chain.get("verdict_correlation")

    wrapper_view = _recording_wrapper_view(sar_id)

    # Derived relationship edges; presence proves the relationship only and adds
    # no authority. An edge is emitted only when both endpoints exist.
    relationships: list[dict[str, Any]] = []
    if continuity_id and sar_id:
        relationships.append(
            {
                "type": "continuity_to_sar",
                "from": continuity_id,
                "to": sar_id,
                "derived": True,
            }
        )
    if sar_id and chain_id:
        relationships.append(
            {"type": "sar_to_chain", "from": sar_id, "to": chain_id, "derived": True}
        )
    if chain_id and sar_verdict is not None:
        relationships.append(
            {
                "type": "chain_to_verdict",
                "from": chain_id,
                "to": "sar_verdict",
                "derived": True,
            }
        )

    notes: list[str] = []
    if sar_verdict is None:
        notes.append("sar_verdict not populated for this chain")
    if continuity_classification is None:
        notes.append("continuity_classification not populated for this chain")
    if verdict_correlation is None:
        notes.append("verdict_correlation not populated for this chain")
    if continuity_id and not continuity_node["present_in_ledger"]:
        notes.append("continuity receipt not present in receipt ledger")
    if sar_id and not sar_node["present_in_ledger"]:
        notes.append("sar receipt not present in receipt ledger")

    return {
        "correlation_schema": CORRELATION_SCHEMA,
        "status": STATUS_RESOLVED,
        "chain_id": chain_id,
        "receipts": receipts,
        "verdicts": {
            "sar_verdict": sar_verdict,
            "continuity_classification": continuity_classification,
            "verdict_correlation": verdict_correlation,
        },
        "recording_wrapper": wrapper_view,
        "authority_boundary_summary": AUTHORITY_BOUNDARY_SUMMARY,
        "relationships": relationships,
        "notes": notes,
    }


def _build_from_receipt(receipt_id: str) -> dict[str, Any]:
    """Assemble a correlation view centered on a receipt with no chain record.

    A receipt can be recorded (and even Path B wrapped) without participating in
    a chain. We report the receipt truthfully with chain fields absent and do
    NOT fabricate a chain, verdicts, or a counterpart receipt."""
    record = svc.find_receipt(receipt_id)
    receipt_type = record.get("receipt_type") if record else None

    # Role is read from the stored receipt_type; not inferred beyond the label.
    if receipt_type == "sar_402_settlement":
        role = "sar"
    elif receipt_type == "continuity":
        role = "continuity"
    else:
        role = "unknown"

    node = {
        "role": role,
        "receipt_id": receipt_id,
        "present_in_ledger": record is not None,
        "receipt_type": receipt_type,
    }

    # Only a SAR receipt can carry a Path B recording wrapper.
    wrapper_view = (
        _recording_wrapper_view(receipt_id)
        if role in ("sar", "unknown")
        else {
            "status": WRAPPER_ABSENT,
            "wrapped_receipt_id": None,
            "authority_boundary_summary": None,
        }
    )

    notes = ["no chain record references this receipt"]
    if record is None:
        notes.append("receipt not present in receipt ledger")

    return {
        "correlation_schema": CORRELATION_SCHEMA,
        "status": STATUS_RESOLVED,
        "chain_id": None,
        "receipts": [node],
        "verdicts": {
            "sar_verdict": None,
            "continuity_classification": None,
            "verdict_correlation": None,
        },
        "recording_wrapper": wrapper_view,
        "authority_boundary_summary": AUTHORITY_BOUNDARY_SUMMARY,
        "relationships": [],
        "notes": notes,
    }


def build_correlation(
    *,
    chain_id: Optional[str] = None,
    receipt_id: Optional[str] = None,
) -> dict[str, Any]:
    """Build the read-only correlation view for one chain or receipt.

    Exactly one of ``chain_id`` / ``receipt_id`` must be provided. Raises
    ``ValueError`` for a missing/ambiguous selector or a structurally invalid id.
    A valid id that matches nothing returns a structured ``not_found`` result
    (never an exception, never a fabricated chain)."""
    if (chain_id is None) == (receipt_id is None):
        raise ValueError("exactly one of chain_id or receipt_id must be provided")

    if chain_id is not None:
        if not _is_valid_chain_id(chain_id):
            raise ValueError(
                f"chain_id must be of the form sha256:<64 hex>; got {chain_id!r}"
            )
        chain = svc.latest_chain_record(chain_id)
        if chain is None:
            return _not_found(chain_id, None)
        return _build_from_chain(chain)

    # receipt_id path
    if not _is_valid_receipt_id(receipt_id):
        raise ValueError(
            "receipt_id must be sha256:<64 hex> or a bare 64-hex hash; "
            f"got {receipt_id!r}"
        )
    chain = _chain_for_receipt(receipt_id)
    if chain is not None:
        return _build_from_chain(chain)
    # Chainless receipt (may still be Path B wrapped): report it truthfully.
    return _build_from_receipt(receipt_id)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="chain_correlation.py",
        description=(
            "Read-only chain correlation view (Evidence Graph Phase 2). Emits a "
            "deterministic JSON correlation view for one chain or receipt to "
            "stdout. It does NOT verify verdicts, authorize, execute, release, "
            "settle, infer verdicts, or mutate any ledger."
        ),
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--chain-id", help="Correlate the chain with this chain_id.")
    group.add_argument(
        "--receipt-id",
        help="Correlate the chain referencing this receipt id (continuity or SAR).",
    )
    return parser


def run(argv: Optional[list[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        view = build_correlation(chain_id=args.chain_id, receipt_id=args.receipt_id)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    # Deterministic serialization: sorted keys, stable indentation, no clock.
    print(json.dumps(view, indent=2, sort_keys=True, ensure_ascii=False))
    return 0 if view.get("status") == STATUS_RESOLVED else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(run())
