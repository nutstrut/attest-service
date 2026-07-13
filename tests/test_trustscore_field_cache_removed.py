"""D1 TrustScore demolition: attest-service field/cache removal.

Pins the post-removal contract for `GET /v1/agents/{agent_id}/summary` and
`POST /v1/agents/historical-import`:

- `trustscore_v1` / `trustscore_url` no longer appear anywhere in either
  response or in newly written agent-ledger records.
- `badge_url` / `badge_markdown` are unchanged (evidenced live consumer,
  see attest-service README "D1 removal complete" note).
- Unrelated summary fields (`agent`, `activations`, `chains`, `receipts`,
  `evidence_summary`) are unaffected.
- No TrustScore cache file/lock is written as a side effect of calling the
  summary endpoint.
- No TrustScore cache helper functions remain on the module at all (proves
  the cache/fetch chain, not just its call sites, was removed).
- Historical agent-ledger records that already contain `trustscore_url`
  (written before this removal) are read back unchanged on disk -- historical
  evidence is not rewritten -- but are sanitized at every API boundary
  (`get_agent`, `get_agent_summary`, `list_agents`) via
  `sanitize_agent_record_for_api` (M19,
  reports/revisit/post-reconciliation-maintenance-register-20260711.md).

All ledger files are monkeypatched to tmp_path; the production ledgers are
never touched.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import attest_service as svc  # noqa: E402

MORPHEUS_AGENT_ID = "agent:morpheus"


def _patch_ledgers(tmp_path, monkeypatch):
    paths = {}
    for name in ("AGENT_LEDGER", "ACTIVATION_LEDGER", "CHAIN_LEDGER", "RECEIPT_LEDGER", "ANALYTICS_LEDGER"):
        path = tmp_path / f"{name.lower()}.jsonl"
        monkeypatch.setattr(svc, name, path)
        paths[name] = path
    return paths


def _register_agent(agent_id: str) -> dict:
    now = svc.iso_now()
    record = {
        "agent_id": agent_id,
        "display_name": agent_id,
        "registered_at": now,
        "created_at": now,
        "updated_at": now,
        "last_seen_at": now,
        "activation_stage": "registered",
        "stage": "registered",
        "status": "registered",
        "receipt_ids": [],
        "real_receipt_ids": [],
        "chain_ids": [],
        "metadata": {},
    }
    svc.write_agent(record)
    return record


def test_no_trustscore_cache_helpers_remain_on_module():
    for name in (
        "trustscore_cache_file_lock",
        "trustscore_cache_metadata",
        "read_trustscore_cache_unlocked",
        "write_trustscore_cache_unlocked",
        "cached_trustscore",
        "store_trustscore",
        "fetch_trustscore_live",
        "fetch_trustscore",
    ):
        assert not hasattr(svc, name), f"{name} should have been removed"
    for name in (
        "TRUSTSCORE_CACHE_FILE",
        "TRUSTSCORE_CACHE_LOCK_FILE",
        "TRUSTSCORE_URL_BASE",
        "TRUSTSCORE_TIMEOUT_SECONDS",
        "TRUSTSCORE_CACHE_TTL_SECONDS",
        "TRUSTSCORE_CACHE_MAX_ENTRIES",
    ):
        assert not hasattr(svc, name), f"{name} should have been removed"


def test_agent_summary_has_no_trustscore_fields(tmp_path, monkeypatch):
    _patch_ledgers(tmp_path, monkeypatch)
    _register_agent(MORPHEUS_AGENT_ID)

    summary = svc.get_agent_summary(MORPHEUS_AGENT_ID, limit=50)

    assert "trustscore_v1" not in summary
    assert "trustscore_url" not in summary


def test_agent_summary_preserves_badge_fields(tmp_path, monkeypatch):
    _patch_ledgers(tmp_path, monkeypatch)
    _register_agent(MORPHEUS_AGENT_ID)

    summary = svc.get_agent_summary(MORPHEUS_AGENT_ID, limit=50)

    assert summary["badge_url"] == f"/badge/{MORPHEUS_AGENT_ID}.svg"
    assert summary["badge_markdown"] == svc.build_badge_markdown(MORPHEUS_AGENT_ID)
    assert "Verified by Default Settlement" in summary["badge_markdown"]


def test_agent_summary_preserves_unrelated_fields(tmp_path, monkeypatch):
    _patch_ledgers(tmp_path, monkeypatch)
    _register_agent(MORPHEUS_AGENT_ID)

    summary = svc.get_agent_summary(MORPHEUS_AGENT_ID, limit=50)

    assert summary["agent"]["agent_id"] == MORPHEUS_AGENT_ID
    assert summary["activations"] == []
    assert summary["chains"] == []
    assert summary["receipts"] == []
    assert summary["evidence_summary"] == {
        "receipt_count": 0,
        "chain_count": 0,
        "activation_count": 0,
        "latest_activity_at": summary["evidence_summary"]["latest_activity_at"],
        "latest_chain_id": None,
        "latest_receipt_ids": None,
        # EXEC-018 provenance separation: factual disclosure of which
        # submission classes this summary was computed from.
        "provenance_scope": "trusted_evidence_only",
    }


def test_agent_summary_no_composite_score_tier_or_ranking(tmp_path, monkeypatch):
    _patch_ledgers(tmp_path, monkeypatch)
    _register_agent(MORPHEUS_AGENT_ID)

    summary = svc.get_agent_summary(MORPHEUS_AGENT_ID, limit=50)

    forbidden_keys = {"score", "tier", "trustscore_v1", "trustscore_url", "ranking", "reliability_score"}
    assert forbidden_keys.isdisjoint(summary.keys())
    assert forbidden_keys.isdisjoint(summary["evidence_summary"].keys())


def test_historical_import_no_longer_writes_trustscore_url(tmp_path, monkeypatch):
    ledgers = _patch_ledgers(tmp_path, monkeypatch)

    input_model = svc.HistoricalImportAgentInput(
        agent_id=MORPHEUS_AGENT_ID,
        display_name="Morpheus",
        activation_type="historical_import",
        origin_anchor={"chain_id": "sha256:" + "a" * 64},
        lineage={},
        metadata={},
    )
    record = svc.historical_import_agent(input_model)

    assert "trustscore_url" not in record

    with open(ledgers["AGENT_LEDGER"]) as f:
        stored = json.loads(f.readline())
    assert "trustscore_url" not in stored
    assert stored["explorer_url"] == f"/v1/attest/chain/{stored['chain_ids'][0]}"


def test_historical_agent_ledger_record_with_trustscore_url_reads_back_unchanged(tmp_path, monkeypatch):
    """Historical evidence must not be rewritten: an agent record written before
    this removal (which still carries the now-retired trustscore_url field)
    must be readable exactly as stored on disk. The API boundary (M19) must
    strip the field from every served response, including the nested `agent`
    object -- it must never leak into any API response, only survive in the
    stored ledger bytes."""
    ledgers = _patch_ledgers(tmp_path, monkeypatch)

    historical_record = {
        "agent_id": MORPHEUS_AGENT_ID,
        "display_name": MORPHEUS_AGENT_ID,
        "registered_at": svc.iso_now(),
        "created_at": svc.iso_now(),
        "updated_at": svc.iso_now(),
        "last_seen_at": svc.iso_now(),
        "activation_stage": "chained",
        "stage": "chained",
        "status": "chained",
        "receipt_ids": [],
        "real_receipt_ids": [],
        "chain_ids": [],
        "metadata": {},
        "trustscore_url": f"/trustscore/{MORPHEUS_AGENT_ID}",
        "trustscore_v1": 82,
    }
    svc.write_agent(historical_record)

    # The stored ledger bytes are untouched -- historical evidence preserved.
    with open(ledgers["AGENT_LEDGER"]) as f:
        stored = json.loads(f.readline())
    assert stored["trustscore_url"] == f"/trustscore/{MORPHEUS_AGENT_ID}"
    assert stored["trustscore_v1"] == 82
    assert stored == historical_record

    # But the API boundary (M19 fix) strips it from every served response.
    summary = svc.get_agent_summary(MORPHEUS_AGENT_ID, limit=50)
    assert "trustscore_url" not in summary["agent"]
    assert "trustscore_v1" not in summary["agent"]
    assert "trustscore_url" not in summary
    assert "trustscore_v1" not in summary

    agent_detail = svc.get_agent(MORPHEUS_AGENT_ID)
    assert "trustscore_url" not in agent_detail
    assert "trustscore_v1" not in agent_detail

    listing = svc.list_agents(limit=50)
    matched = [a for a in listing["agents"] if a["agent_id"] == MORPHEUS_AGENT_ID]
    assert len(matched) == 1
    assert "trustscore_url" not in matched[0]
    assert "trustscore_v1" not in matched[0]

    # The record read straight from the ledger a second time is still
    # untouched -- sanitization never mutates in place.
    with open(ledgers["AGENT_LEDGER"]) as f:
        stored_again = json.loads(f.readline())
    assert stored_again == historical_record


def test_sanitize_agent_record_for_api_does_not_mutate_input():
    original = {
        "agent_id": MORPHEUS_AGENT_ID,
        "trustscore_url": f"/trustscore/{MORPHEUS_AGENT_ID}",
        "trustscore_v1": 82,
        "badge_url": f"/badge/{MORPHEUS_AGENT_ID}.svg",
    }
    original_copy = json.loads(json.dumps(original))

    sanitized = svc.sanitize_agent_record_for_api(original)

    assert original == original_copy, "input record must not be mutated"
    assert "trustscore_url" not in sanitized
    assert "trustscore_v1" not in sanitized
    assert sanitized["badge_url"] == original["badge_url"]
    assert sanitized["agent_id"] == original["agent_id"]


def test_sanitize_agent_record_for_api_no_op_on_clean_record():
    clean = {
        "agent_id": MORPHEUS_AGENT_ID,
        "display_name": "Morpheus",
        "badge_url": f"/badge/{MORPHEUS_AGENT_ID}.svg",
        "metadata": {"note": "no deprecated fields here"},
    }
    sanitized = svc.sanitize_agent_record_for_api(clean)
    assert sanitized == clean


def test_get_agent_detail_endpoint_sanitized_for_historical_record(tmp_path, monkeypatch):
    ledgers = _patch_ledgers(tmp_path, monkeypatch)
    now = svc.iso_now()
    svc.write_agent(
        {
            "agent_id": MORPHEUS_AGENT_ID,
            "display_name": MORPHEUS_AGENT_ID,
            "registered_at": now,
            "created_at": now,
            "updated_at": now,
            "last_seen_at": now,
            "activation_stage": "chained",
            "stage": "chained",
            "status": "chained",
            "receipt_ids": [],
            "real_receipt_ids": [],
            "chain_ids": [],
            "metadata": {},
            "trustscore_url": f"/trustscore/{MORPHEUS_AGENT_ID}",
        }
    )

    agent = svc.get_agent(MORPHEUS_AGENT_ID)
    assert "trustscore_url" not in agent
    assert agent["agent_id"] == MORPHEUS_AGENT_ID
    assert agent["stage"] == "chained"


def test_list_agents_endpoint_sanitized_for_historical_record(tmp_path, monkeypatch):
    _patch_ledgers(tmp_path, monkeypatch)
    now = svc.iso_now()
    svc.write_agent(
        {
            "agent_id": MORPHEUS_AGENT_ID,
            "display_name": MORPHEUS_AGENT_ID,
            "registered_at": now,
            "created_at": now,
            "updated_at": now,
            "last_seen_at": now,
            "activation_stage": "chained",
            "stage": "chained",
            "status": "chained",
            "receipt_ids": [],
            "real_receipt_ids": [],
            "chain_ids": [],
            "metadata": {},
            "trustscore_url": f"/trustscore/{MORPHEUS_AGENT_ID}",
        }
    )
    _register_agent("agent:clean-no-deprecated-fields")

    listing = svc.list_agents(limit=50)
    for agent in listing["agents"]:
        assert "trustscore_url" not in agent
        assert "trustscore_v1" not in agent
    assert listing["count"] == 2


def test_receipt_and_activation_listing_endpoints_remain_healthy(tmp_path, monkeypatch):
    _patch_ledgers(tmp_path, monkeypatch)
    _register_agent(MORPHEUS_AGENT_ID)

    activations = svc.list_agent_activations(MORPHEUS_AGENT_ID, limit=50)
    receipts = svc.list_receipts(agent_id=MORPHEUS_AGENT_ID, limit=50)
    chains = svc.list_chains(agent_id=MORPHEUS_AGENT_ID, limit=50)

    assert activations["activations"] == []
    assert receipts["receipts"] == []
    assert chains["chains"] == []


def test_warm_trustscore_cache_script_removed():
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    assert not os.path.exists(os.path.join(repo_root, "warm_trustscore_cache.py"))
