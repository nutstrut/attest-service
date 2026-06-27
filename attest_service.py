from __future__ import annotations

import copy
import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from contextlib import contextmanager
from typing import Any, Literal, get_args
from urllib.parse import quote
from uuid import uuid4

import requests
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

try:
    import fcntl
except ImportError:
    fcntl = None

SERVICE = "attest-service"
VERSION = "0.2"

BASE_DIR = Path(__file__).resolve().parent
SESSION_LEDGER = BASE_DIR / "attest_sessions_master.jsonl"
AGENT_LEDGER = BASE_DIR / "agent_registry_master.jsonl"
ACTIVATION_LEDGER = BASE_DIR / "agent_activation_master.jsonl"
ANALYTICS_LEDGER = BASE_DIR / "activation_analytics_master.jsonl"
CHAIN_LEDGER = BASE_DIR / "attest_chains_master.jsonl"
RECEIPT_LEDGER = BASE_DIR / "attest_receipts_master.jsonl"
TRUSTSCORE_CACHE_FILE = BASE_DIR / "trustscore_cache.json"
TRUSTSCORE_CACHE_LOCK_FILE = BASE_DIR / "trustscore_cache.lock"

CONTINUITY_EVALUATE_URL = "http://127.0.0.1:3002/continuity/evaluate"
CONTINUITY_CHAIN_URL = "http://127.0.0.1:3002/continuity/chain"
SAR_URL = "http://127.0.0.1:3001/settlement-witness"
TRUSTSCORE_URL_BASE = "http://127.0.0.1:3001/trustscore"

HTTP_TIMEOUT_SECONDS = 15
TRUSTSCORE_TIMEOUT_SECONDS = 1.0
TRUSTSCORE_CACHE_TTL_SECONDS = 300
TRUSTSCORE_CACHE_MAX_ENTRIES = 256
DEFAULT_LIMIT = 50
MAX_LIMIT = 200
DEFAULT_EXTERNAL_VERIFIER = "Default Settlement"

ActivationStage = Literal["registered", "activated", "activation_failed", "verified", "chained", "continuous"]
ReceiptContext = Literal["activation_demo", "real_task", "continuity_pair", "public_demo"]

STAGE_ORDER = {
    "registered": 0,
    "activation_failed": 0,
    "activated": 1,
    "verified": 2,
    "chained": 3,
    "continuous": 4,
}

app = FastAPI(title=SERVICE, version=VERSION)

# Controlled SAR-402 demo loop: /pay/url-summary. The route feeds delivery +
# (demo) payment evidence into the committed Morpheus SAR-402 ingestion layer;
# it never hand-writes receipts.
from pay_url_summary import router as pay_url_summary_router  # noqa: E402

app.include_router(pay_url_summary_router)

# Public SAR-402 ingestion surface: POST /v1/sar-402/receipts. External x402
# resource-server middleware submits a normalized, resource-server-built SAR-402
# receipt; DefaultVerifier validates (committed schema + authority boundary) and
# records it. The verifier never executes, authorizes, or controls delivery.
from sar402_receipts import router as sar402_receipts_router  # noqa: E402

app.include_router(sar402_receipts_router)

# SAR-402 Path B read surface: GET /v1/sar-402/recording/{receipt_id}. A public,
# read-only lookup that returns the stored recording-attribution wrapper for an
# inner receipt (Path B is NOT live; this serves only locally/test-stored
# wrappers). It never creates, signs, or mutates wrappers, never touches Path A
# storage, and never creates or requires production keys.
import os as _os  # noqa: E402

import sar402_recording_store as recording_store  # noqa: E402
from sar402_recording_wrapper import (  # noqa: E402
    load_public_key as _load_recording_public_key,
    verify_recording_wrapper,
)

# Hosted Path C, Step 1: the Action Commitment / committed-request registry.
# Public read/write surface that preserves the committed request/action chain
# (body_digest -> request_digest -> action_ref) so a LATER hosted deterministic
# evaluator can retrieve the committed acceptance spec by action_ref. This
# registry does NOT evaluate, does NOT sign, and does NOT prove execution,
# spec satisfaction, or release. It uses its own append-only ledger.
import action_commitment_store as commitment_store  # noqa: E402
from action_commitment_store import (  # noqa: E402
    ActionCommitmentConflict,
    ActionCommitmentRecordError,
)

# Hosted Path C, Step 2A: UNSIGNED deterministic evaluation. The evaluator
# retrieves the committed acceptance spec by action_ref from the Action
# Commitment record and NEVER accepts a caller-submitted acceptance_spec (that
# would allow spec substitution). Step 2A does NOT sign, does NOT issue a
# Continuity Evaluation Receipt, and claims no payment / release / execution /
# correctness / legal finality.
import deterministic_evaluator as det_evaluator  # noqa: E402
import deterministic_evaluation_store as evaluation_store  # noqa: E402
from deterministic_evaluator import DeterministicEvaluationError  # noqa: E402
from deterministic_evaluation_store import (  # noqa: E402
    DeterministicEvaluationConflict,
    DeterministicEvaluationRecordError,
)

# Hosted Path C, Step 2B: SIGNED Continuity Evaluation Receipt issuance over an
# already-stored UNSIGNED Step 2A record. Signs with the configured evaluator's
# Ed25519 key (ds.continuity_evaluation.v0.1). Fails safely when key material is
# missing — it never emits an unsigned/partial receipt. It does NOT alter the
# Step 2A record and claims no release / payment / execution / correctness /
# legal finality.
import continuity_evaluation_receipts as continuity_receipts  # noqa: E402
from continuity_evaluation_receipts import (  # noqa: E402
    ContinuityReceiptConfigError,
    ContinuityReceiptConflict,
    ContinuityReceiptError,
    ContinuityReceiptVerificationError,
)


def _recording_public_key():
    """Return the recording-attribution VERIFICATION (public) key, or None.

    Loaded from ``SAR402_RECORDING_PUBLIC_KEY_HEX`` only (no default, no embedded
    key, never a private/production key). Returns None when unconfigured, which
    the endpoint surfaces as a 503. Tests inject an ephemeral test public key by
    monkeypatching this function."""
    return _load_recording_public_key(_os.environ)


def _is_valid_receipt_id(receipt_id: str) -> bool:
    """Inner SAR-402 receipt ids are adopted content hashes: ``sha256:<64 hex>``."""
    if not isinstance(receipt_id, str) or not receipt_id.startswith("sha256:"):
        return False
    hexpart = receipt_id[len("sha256:"):]
    return len(hexpart) == 64 and all(c in "0123456789abcdef" for c in hexpart)


@contextmanager
def trustscore_cache_file_lock():
    TRUSTSCORE_CACHE_LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    with TRUSTSCORE_CACHE_LOCK_FILE.open("a+", encoding="utf-8") as f:
        if fcntl:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            if fcntl:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)


def trustscore_cache_metadata(cached_at: float, state: str) -> dict[str, Any]:
    return {
        "state": state,
        "cached_at": datetime.fromtimestamp(cached_at, timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "age_seconds": max(0, int(time.time() - cached_at)),
        "source": "settlement-witness",
    }


def read_trustscore_cache_unlocked() -> dict[str, Any]:
    if not TRUSTSCORE_CACHE_FILE.exists():
        return {}
    try:
        data = json.loads(TRUSTSCORE_CACHE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    entries = data.get("entries") if isinstance(data, dict) else None
    return entries if isinstance(entries, dict) else {}


def write_trustscore_cache_unlocked(entries: dict[str, Any]) -> None:
    TRUSTSCORE_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": 1,
        "updated_at": iso_now(),
        "entries": entries,
    }
    tmp_path = TRUSTSCORE_CACHE_FILE.with_name(f".{TRUSTSCORE_CACHE_FILE.name}.{uuid4().hex}.tmp")
    try:
        tmp_path.write_text(json.dumps(payload, separators=(",", ":"), ensure_ascii=False), encoding="utf-8")
        tmp_path.replace(TRUSTSCORE_CACHE_FILE)
    finally:
        if tmp_path.exists():
            tmp_path.unlink()


def cached_trustscore(agent_id: str) -> tuple[dict[str, Any], float] | None:
    with trustscore_cache_file_lock():
        entry = read_trustscore_cache_unlocked().get(agent_id)
    if not isinstance(entry, dict):
        return None
    trustscore = entry.get("trustscore_v1")
    cached_at = entry.get("cached_at")
    if not isinstance(trustscore, dict) or not isinstance(cached_at, (int, float)):
        return None
    return copy.deepcopy(trustscore), float(cached_at)


def store_trustscore(agent_id: str, trustscore: dict[str, Any]) -> dict[str, Any]:
    trustscore_copy = copy.deepcopy(trustscore)
    with trustscore_cache_file_lock():
        entries = read_trustscore_cache_unlocked()
        if agent_id in entries:
            entries.pop(agent_id)
        elif len(entries) >= TRUSTSCORE_CACHE_MAX_ENTRIES:
            oldest_agent_id = min(entries, key=lambda key: entries[key].get("cached_at", 0) if isinstance(entries[key], dict) else 0)
            entries.pop(oldest_agent_id)
        entries[agent_id] = {
            "trustscore_v1": trustscore_copy,
            "cached_at": time.time(),
        }
        write_trustscore_cache_unlocked(entries)
    return copy.deepcopy(trustscore_copy)


def fetch_trustscore_live(agent_id: str) -> dict[str, Any] | None:
    try:
        r = requests.get(f"{TRUSTSCORE_URL_BASE}/{quote(agent_id, safe='')}", timeout=TRUSTSCORE_TIMEOUT_SECONDS)
        if r.status_code >= 400:
            return None
        data = r.json()
        ts = data.get("trustscore_v1")
        return ts if isinstance(ts, dict) else None
    except (requests.RequestException, ValueError):
        return None


def fetch_trustscore(agent_id: str) -> dict[str, Any] | None:
    cached = cached_trustscore(agent_id)
    if cached:
        cached_score, cached_at = cached
        if time.time() - cached_at < TRUSTSCORE_CACHE_TTL_SECONDS:
            return cached_score

    live_score = fetch_trustscore_live(agent_id)
    if live_score is not None:
        return store_trustscore(agent_id, live_score)

    if cached:
        cached_score, cached_at = cached
        cached_score["_cache"] = trustscore_cache_metadata(cached_at, "stale")
        return cached_score

    return None

def iso_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def seconds_between(start: str | None, end: str | None) -> int | None:
    start_dt = parse_iso(start)
    end_dt = parse_iso(end)
    if not start_dt or not end_dt:
        return None
    return int((end_dt - start_dt).total_seconds())


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        if fcntl:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            f.write(json.dumps(record, separators=(",", ":"), ensure_ascii=False) + "\n")
            f.flush()
        finally:
            if fcntl:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


def bounded_limit(limit: int | None) -> int:
    if limit is None:
        return DEFAULT_LIMIT
    if limit < 1:
        raise HTTPException(status_code=400, detail="limit must be at least 1")
    return min(limit, MAX_LIMIT)


def latest_by(records: list[dict[str, Any]], key: str, value: str) -> dict[str, Any] | None:
    latest = None
    for rec in records:
        if rec.get(key) == value:
            latest = rec
    return latest


def latest_session(session_id: str) -> dict[str, Any] | None:
    return latest_by(read_jsonl(SESSION_LEDGER), "session_id", session_id)


def latest_agent(agent_id: str) -> dict[str, Any] | None:
    return latest_by(read_jsonl(AGENT_LEDGER), "agent_id", agent_id)


def latest_activation(activation_id: str) -> dict[str, Any] | None:
    return latest_by(read_jsonl(ACTIVATION_LEDGER), "activation_id", activation_id)


def latest_receipt(receipt_id: str) -> dict[str, Any] | None:
    return latest_by(read_jsonl(RECEIPT_LEDGER), "receipt_id", receipt_id)


def contains_receipt_id(value: Any, receipt_id: str) -> bool:
    if isinstance(value, dict):
        for key, nested_value in value.items():
            if key == "receipt_id" and nested_value == receipt_id:
                return True
            if contains_receipt_id(nested_value, receipt_id):
                return True
    if isinstance(value, list):
        return any(contains_receipt_id(item, receipt_id) for item in value)
    return False


def find_receipt(receipt_id: str) -> dict[str, Any] | None:
    latest = None
    for record in read_jsonl(RECEIPT_LEDGER):
        if contains_receipt_id(record, receipt_id):
            latest = record
    return latest


def latest_chain_record(chain_id: str) -> dict[str, Any] | None:
    return latest_by(read_jsonl(CHAIN_LEDGER), "chain_id", chain_id)


def sorted_recent(records: list[dict[str, Any]], field: str, limit: int) -> list[dict[str, Any]]:
    return sorted(records, key=lambda rec: rec.get(field) or "", reverse=True)[:limit]


def sorted_agents(records: list[dict[str, Any]], limit: int) -> list[dict[str, Any]]:
    return sorted(
        records,
        key=lambda rec: (STAGE_ORDER.get(rec.get("activation_stage", "registered"), -1), rec.get("updated_at") or ""),
        reverse=True,
    )[:limit]


def post_json(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    resp = requests.post(url, json=payload, timeout=HTTP_TIMEOUT_SECONDS)
    try:
        data = resp.json()
    except ValueError:
        data = {"error": resp.text}
    if resp.status_code >= 400:
        raise HTTPException(status_code=502, detail=data)
    return data


def get_json(url: str) -> dict[str, Any]:
    resp = requests.get(url, timeout=HTTP_TIMEOUT_SECONDS)
    try:
        data = resp.json()
    except ValueError:
        data = {"error": resp.text}
    if resp.status_code >= 400:
        raise HTTPException(status_code=502, detail=data)
    return data


def stage_at_least(stage: str, minimum: str) -> bool:
    return STAGE_ORDER.get(stage, -1) >= STAGE_ORDER[minimum]


def registry_record(
    existing: dict[str, Any] | None,
    *,
    agent_id: str,
    owner_id: str,
    counterparty: str,
    display_name: str | None,
    stage: ActivationStage,
    metadata: dict[str, Any],
    latest_activation_id: str | None = None,
    latest_chain_id: str | None = None,
    latest_continuity_receipt_id: str | None = None,
    latest_sar_receipt_id: str | None = None,
) -> dict[str, Any]:
    now = iso_now()
    return {
        "agent_id": agent_id,
        # Forward-compatible activation provenance. Allowed values: native,
        # historical_import.
        "activation_type": (existing or {}).get("activation_type") or "native",
        "owner_id": owner_id,
        "counterparty": counterparty,
        "display_name": display_name,
        "activation_stage": stage,
        "stage": stage,
        "status": stage,
        "registered_at": (existing or {}).get("registered_at") or now,
        "created_at": (existing or {}).get("created_at") or now,
        "updated_at": now,
        "metadata": metadata,
        "latest_activation_id": latest_activation_id if latest_activation_id is not None else (existing or {}).get("latest_activation_id"),
        "latest_chain_id": latest_chain_id if latest_chain_id is not None else (existing or {}).get("latest_chain_id"),
        "latest_continuity_receipt_id": latest_continuity_receipt_id
        if latest_continuity_receipt_id is not None
        else (existing or {}).get("latest_continuity_receipt_id"),
        "latest_sar_receipt_id": latest_sar_receipt_id if latest_sar_receipt_id is not None else (existing or {}).get("latest_sar_receipt_id"),
    }


def write_agent(record: dict[str, Any]) -> dict[str, Any]:
    append_jsonl(AGENT_LEDGER, record)
    return record


def write_analytics(
    *,
    agent_id: str,
    activation_id: str | None,
    event_type: str,
    receipt_context: str | None = None,
    from_stage: str | None = None,
    to_stage: str | None = None,
    elapsed_ms: int | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    record = {
        "event_id": "activation_event:" + uuid4().hex,
        "agent_id": agent_id,
        "activation_id": activation_id,
        "event_type": event_type,
        "receipt_context": receipt_context,
        "from_stage": from_stage,
        "to_stage": to_stage,
        "occurred_at": iso_now(),
        "elapsed_ms": elapsed_ms,
        "metadata": metadata or {},
    }
    append_jsonl(ANALYTICS_LEDGER, record)
    return record


def write_receipt(
    *,
    receipt: dict[str, Any],
    receipt_type: str,
    receipt_context: ReceiptContext,
    agent_id: str | None = None,
    activation_id: str | None = None,
    chain_id: str | None = None,
    external_provenance: dict[str, Any] | None = None,
) -> None:
    receipt_id = receipt.get("receipt_id")
    if not receipt_id:
        return
    record = {
        "receipt_id": receipt_id,
        "receipt_type": receipt_type,
        "receipt_context": receipt_context,
        "agent_id": agent_id,
        "activation_id": activation_id,
        "chain_id": chain_id,
        "created_at": iso_now(),
        "receipt": receipt,
    }
    if external_provenance:
        record["external_provenance"] = external_provenance
    append_jsonl(RECEIPT_LEDGER, record)


def write_chain(
    *,
    chain_id: str,
    agent_id: str | None,
    activation_id: str | None,
    continuity_receipt_id: str | None,
    sar_receipt_id: str | None,
    stage: str,
    receipt_context: ReceiptContext,
    time_delta_seconds: int | float | None = None,
    continuity_classification: str | None = None,
    sar_verdict: str | None = None,
    verdict_correlation: str | None = None,
    predicate_status_vector: dict[str, Any] | list[Any] | None = None,
    external_provenance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    record = {
        "chain_id": chain_id,
        "agent_id": agent_id,
        "activation_id": activation_id,
        "continuity_receipt_id": continuity_receipt_id,
        "sar_receipt_id": sar_receipt_id,
        "time_delta_seconds": time_delta_seconds,
        "continuity_classification": continuity_classification,
        "sar_verdict": sar_verdict,
        "verdict_correlation": verdict_correlation,
        "predicate_status_vector": predicate_status_vector,
        "stage": stage,
        "receipt_context": receipt_context,
        "created_at": iso_now(),
    }
    if external_provenance:
        record["external_provenance"] = external_provenance
    append_jsonl(CHAIN_LEDGER, record)
    return record


def local_chain_context(chain_id: str) -> dict[str, Any] | None:
    chain = latest_chain_record(chain_id)
    if chain:
        return chain
    for record in reversed(read_jsonl(ACTIVATION_LEDGER)):
        if record.get("chain_id") == chain_id:
            return record
    for record in reversed(read_jsonl(AGENT_LEDGER)):
        if record.get("latest_chain_id") == chain_id:
            return record
    return None


def chain_response(chain_id: str) -> dict[str, Any]:
    local_record = local_chain_context(chain_id)
    try:
        response = get_json(f"{CONTINUITY_CHAIN_URL}/{chain_id}")
    except Exception:
        if not local_record:
            raise
        response = {"chain_id": chain_id, "chain_status": "lookup_unavailable"}

    if local_record:
        response = dict(response)
        response["attest_chain_record"] = local_record
        if local_record.get("external_provenance"):
            response["external_provenance"] = local_record["external_provenance"]
    return response


def chain_lookup(chain_id: str) -> dict[str, Any]:
    try:
        return get_json(f"{CONTINUITY_CHAIN_URL}/{chain_id}")
    except Exception:
        return {"chain_id": chain_id, "chain_status": "lookup_unavailable"}


def activation_continuity_input(continuity_input: dict[str, Any], agent_id: str) -> dict[str, Any]:
    payload = copy.deepcopy(continuity_input)
    subject = payload.get("subject")
    if not isinstance(subject, dict):
        subject = {}
    subject["subject_id"] = agent_id
    subject["subject_type"] = subject.get("subject_type") or "agent"
    payload["subject"] = subject

    payload["schema_version"] = payload.get("schema_version") or "0.1"
    if not isinstance(payload.get("receipts"), list):
        payload["receipts"] = []

    default_action = {"operation": "activate_agent", "agent_id": agent_id}
    requested_action = payload.get("spec") if isinstance(payload.get("spec"), dict) else default_action
    executed_action = payload.get("output") if isinstance(payload.get("output"), dict) else requested_action
    execution_path = payload.get("execution_path")
    if not isinstance(execution_path, dict):
        execution_path = {}
    execution_path["action_id"] = execution_path.get("action_id") or payload.get("task_id") or f"activate-agent:{agent_id}"
    execution_path["requested_action"] = execution_path.get("requested_action") or requested_action
    execution_path["admitted_action"] = execution_path.get("admitted_action") or requested_action
    execution_path["executed_action"] = execution_path.get("executed_action") or executed_action
    execution_path["mutation_boundary_ts"] = execution_path.get("mutation_boundary_ts") or payload.get("mutation_boundary_ts") or iso_now()
    execution_path["executor_id"] = execution_path.get("executor_id") or payload.get("executor_id") or "defaultverifier-activation-v1"
    if "execution_environment" not in execution_path:
        execution_path["execution_environment"] = payload.get("execution_environment")
    payload["execution_path"] = execution_path

    if not isinstance(payload.get("mutation_events"), list):
        payload["mutation_events"] = []

    evaluation_context = payload.get("evaluation_context")
    if not isinstance(evaluation_context, dict):
        evaluation_context = {}
    evaluation_context["evaluated_at"] = evaluation_context.get("evaluated_at") or payload.get("evaluated_at") or execution_path["mutation_boundary_ts"]
    evaluation_context["policy_ref"] = evaluation_context.get("policy_ref") or payload.get("policy_ref") or "agent-activation-v1"
    evaluation_context["expected_verifier_id"] = (
        evaluation_context.get("expected_verifier_id")
        or payload.get("expected_verifier_id")
        or "defaultverifier-continuity-v1"
    )
    payload["evaluation_context"] = evaluation_context
    return payload


def first_present(record: dict[str, Any], keys: list[str]) -> Any:
    for key in keys:
        value = record.get(key)
        if value is not None:
            return value
    return None


def dict_or_empty(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def external_receipt_id(value: Any) -> Any:
    if isinstance(value, dict):
        return first_present(value, ["receipt_id", "external_receipt_id", "id"])
    if isinstance(value, str):
        return value
    return None


def external_provenance_from_payload(
    *,
    sar_input: dict[str, Any] | None = None,
    continuity_input: dict[str, Any] | None = None,
    origin_anchor: dict[str, Any] | None = None,
    lineage: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    sar_input = dict_or_empty(sar_input)
    sar_spec = dict_or_empty(sar_input.get("spec"))
    continuity_input = dict_or_empty(continuity_input)
    execution_path = dict_or_empty(continuity_input.get("execution_path"))
    origin_anchor = dict_or_empty(origin_anchor)
    lineage = dict_or_empty(lineage)

    external_receipt = first_present(sar_spec, ["external_receipt"]) or first_present(sar_input, ["external_receipt"])
    external_issuer = (
        first_present(sar_spec, ["external_issuer"])
        or first_present(sar_input, ["external_issuer"])
        or first_present(origin_anchor, ["external_issuer"])
        or first_present(lineage, ["external_issuer"])
    )
    observed_by = (
        first_present(sar_spec, ["observed_by"])
        or first_present(sar_input, ["observed_by"])
        or first_present(origin_anchor, ["observed_by"])
        or first_present(lineage, ["observed_by"])
    )
    verified_by = (
        first_present(sar_spec, ["verified_by"])
        or first_present(sar_input, ["verified_by"])
        or first_present(origin_anchor, ["verified_by"])
        or first_present(lineage, ["verified_by"])
    )
    provenance = (
        first_present(sar_spec, ["provenance"])
        or first_present(sar_input, ["provenance"])
        or first_present(origin_anchor, ["provenance"])
        or first_present(lineage, ["provenance"])
    )
    counterparty = (
        first_present(sar_input, ["counterparty"])
        or first_present(sar_spec, ["counterparty"])
        or first_present(origin_anchor, ["counterparty"])
        or first_present(lineage, ["counterparty"])
    )
    receipt_id = (
        external_receipt_id(external_receipt)
        or first_present(sar_spec, ["external_receipt_id"])
        or first_present(sar_input, ["external_receipt_id"])
        or first_present(origin_anchor, ["external_receipt_id", "receipt_id"])
        or first_present(lineage, ["external_receipt_id", "receipt_id"])
    )

    action_fields = {
        key: execution_path[key]
        for key in ("requested_action", "admitted_action", "executed_action")
        if key in execution_path and execution_path[key] is not None
    }
    if not any([external_receipt, external_issuer, observed_by, verified_by, provenance, receipt_id]):
        return None

    normalized = {
        "source_type": "external_sar_receipt",
        "external_issuer": external_issuer,
        "external_receipt_id": receipt_id,
        "observed_by": observed_by,
        "verified_by": verified_by or DEFAULT_EXTERNAL_VERIFIER,
        "provenance": provenance,
        "counterparty": counterparty,
    }
    if isinstance(external_receipt, dict):
        normalized["external_receipt"] = external_receipt
    if action_fields:
        normalized["execution_path"] = action_fields
    return {key: value for key, value in normalized.items() if value is not None}


def verdict_correlation(continuity_value: Any, sar_value: Any) -> str:
    if continuity_value is None or sar_value is None:
        return "unknown"
    continuity_text = str(continuity_value).lower()
    sar_text = str(sar_value).lower()
    passing = {"pass", "passed", "ok", "success", "linked"}
    failing = {"fail", "failed", "error", "rejected"}
    if continuity_text in passing and sar_text in passing:
        return "consistent_pass"
    if continuity_text in failing and sar_text in failing:
        return "consistent_fail"
    return "divergent"


def nested_value(record: dict[str, Any], path: list[str]) -> Any:
    value: Any = record
    for key in path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def sar_verdict_value(sar: dict[str, Any]) -> Any:
    return first_present(
        sar,
        ["verdict", "status", "result"],
    ) or nested_value(sar, ["receipt_v0_1", "verdict"])


def sar_reason_code(sar: dict[str, Any]) -> Any:
    return first_present(sar, ["reason_code", "reason"]) or nested_value(sar, ["receipt_v0_1", "reason_code"])


def activation_sar_claim(
    *,
    agent_id: str,
    activation_id: str,
    receipt_context: str,
    continuity_receipt_id: str,
    activation_spec: dict[str, Any],
    activation_output: dict[str, Any],
) -> dict[str, Any]:
    stage = activation_output.get("stage") or activation_spec.get("stage") or "activated"
    return {
        "agent_id": agent_id,
        "activation_id": activation_id,
        "stage": stage,
        "receipt_context": receipt_context,
        "continuity_receipt_id": continuity_receipt_id,
    }


def record_failed_activation(
    *,
    agent: dict[str, Any],
    agent_id: str,
    activation_id: str,
    receipt_context: ReceiptContext,
    metadata: dict[str, Any],
    error: Any,
    continuity_receipt_id: str | None = None,
    sar_receipt_id: str | None = None,
    sar_verdict: Any = None,
    reason_code: Any = None,
    elapsed_ms: int | None = None,
) -> dict[str, Any]:
    now = iso_now()
    error_detail = error if isinstance(error, (str, int, float, bool, dict, list)) or error is None else str(error)
    activation_record = {
        "activation_id": activation_id,
        "agent_id": agent_id,
        "activation_type": agent.get("activation_type") or "native",
        "stage": "activation_failed",
        "activation_stage": "activation_failed",
        "status": "failed",
        "receipt_context": receipt_context,
        "continuity_receipt_id": continuity_receipt_id,
        "sar_receipt_id": sar_receipt_id,
        "sar_verdict": sar_verdict,
        "reason_code": reason_code,
        "error": error_detail,
        "chain_id": None,
        "created_at": now,
        "updated_at": now,
        "metadata": metadata,
    }
    append_jsonl(ACTIVATION_LEDGER, activation_record)
    failed_agent = registry_record(
        agent,
        agent_id=agent_id,
        owner_id=agent["owner_id"],
        counterparty=agent["counterparty"],
        display_name=agent.get("display_name"),
        stage="activation_failed",
        metadata=agent.get("metadata", {}),
        latest_activation_id=activation_id,
        latest_continuity_receipt_id=continuity_receipt_id,
        latest_sar_receipt_id=sar_receipt_id,
    )
    failed_agent["status"] = "activation_failed"
    write_agent(failed_agent)
    write_analytics(
        agent_id=agent_id,
        activation_id=activation_id,
        event_type="activation_failed",
        receipt_context=receipt_context,
        from_stage=agent.get("activation_stage"),
        to_stage="activation_failed",
        elapsed_ms=elapsed_ms,
        metadata={"error": error_detail, "sar_verdict": sar_verdict, "reason_code": reason_code},
    )
    return activation_record


def is_sar_pass(sar: dict[str, Any]) -> bool:
    verdict = sar_verdict_value(sar)
    return str(verdict).upper() == "PASS"


def build_badge_markdown(agent_id: str) -> str:
    return (
        f"[![Verified by Default Settlement](https://defaultverifier.com/badge/{agent_id}.svg)]"
        f"(https://defaultverifier.com/trustscore/{agent_id})"
    )


class SyncAttestInput(BaseModel):
    continuity_input: dict[str, Any]
    sar_input: dict[str, Any]
    receipt_context: ReceiptContext = "real_task"


class BeginInput(BaseModel):
    continuity_input: dict[str, Any]
    metadata: dict[str, Any] = Field(default_factory=dict)
    receipt_context: ReceiptContext = "real_task"


class CompleteInput(BaseModel):
    session_id: str
    sar_input: dict[str, Any]
    receipt_context: ReceiptContext | None = None


class RegisterAgentInput(BaseModel):
    agent_id: str | None = None
    owner_id: str
    counterparty: str
    display_name: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class HistoricalImportAgentInput(BaseModel):
    agent_id: str
    display_name: str | None = None
    activation_type: str
    origin_anchor: dict[str, Any]
    lineage: dict[str, Any]
    metadata: dict[str, Any] = Field(default_factory=dict)


class ActivateAgentInput(BaseModel):
    receipt_context: Literal["activation_demo", "real_task"] = "activation_demo"
    continuity_input: dict[str, Any]
    activation_spec: dict[str, Any] = Field(default_factory=dict)
    activation_output: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ContinuityPairInput(BaseModel):
    receipt_context: Literal["continuity_pair"] = "continuity_pair"
    continuity_input: dict[str, Any]
    previous_activation_id: str | None = None
    previous_chain_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


@app.get("/healthz")
def healthz():
    return {"ok": True, "service": SERVICE, "version": VERSION}


@app.post("/v1/attest")
def attest(input: SyncAttestInput):
    t0 = time.perf_counter()
    continuity = post_json(CONTINUITY_EVALUATE_URL, input.continuity_input)
    continuity_receipt_id = continuity.get("receipt_id")
    if not continuity_receipt_id:
        raise HTTPException(status_code=502, detail="continuity receipt_id missing")
    sar_payload = dict(input.sar_input)
    sar_payload["continuity_receipt_id"] = continuity_receipt_id
    sar_payload["receipt_context"] = input.receipt_context
    external_provenance = external_provenance_from_payload(sar_input=sar_payload, continuity_input=input.continuity_input)
    sar = post_json(SAR_URL, sar_payload)
    sar_receipt_id = sar.get("receipt_id")
    if not sar_receipt_id:
        raise HTTPException(status_code=502, detail="settlement-witness receipt_id missing")

    chain_id = sha256_text(continuity_receipt_id + sar_receipt_id)
    chain = chain_lookup(chain_id)
    write_chain(
        chain_id=chain_id,
        agent_id=sar_payload.get("agent_id"),
        activation_id=sar_payload.get("activation_id"),
        continuity_receipt_id=continuity_receipt_id,
        sar_receipt_id=sar_receipt_id,
        stage="chained",
        receipt_context=input.receipt_context,
        external_provenance=external_provenance,
    )
    if external_provenance:
        chain = {**chain, "external_provenance": external_provenance}
    write_receipt(receipt=continuity, receipt_type="continuity", receipt_context=input.receipt_context, chain_id=chain_id)
    write_receipt(
        receipt=sar,
        receipt_type="sar",
        receipt_context=input.receipt_context,
        chain_id=chain_id,
        external_provenance=external_provenance,
    )

    return {
        "service": SERVICE,
        "version": VERSION,
        "mode": "sync",
        "status": "complete",
        "receipt_context": input.receipt_context,
        "elapsed_ms": int((time.perf_counter() - t0) * 1000),
        "continuity": continuity,
        "sar": sar,
        "chain": chain,
    }


@app.post("/v1/attest/begin")
def begin(input: BeginInput):
    continuity = post_json(CONTINUITY_EVALUATE_URL, input.continuity_input)
    continuity_receipt_id = continuity.get("receipt_id")
    external_provenance = external_provenance_from_payload(continuity_input=input.continuity_input)

    if not continuity_receipt_id:
        raise HTTPException(status_code=502, detail="continuity receipt_id missing")

    session_id = "attest_session:" + uuid4().hex

    session_record = {
        "session_id": session_id,
        "status": "pending",
        "receipt_context": input.receipt_context,
        "continuity_receipt_id": continuity_receipt_id,
        "metadata": input.metadata,
        "created_at": iso_now(),
    }
    if external_provenance:
        session_record["external_provenance"] = external_provenance
    append_jsonl(SESSION_LEDGER, session_record)
    write_receipt(receipt=continuity, receipt_type="continuity", receipt_context=input.receipt_context)

    return {"session_id": session_id, "status": "pending", "receipt_context": input.receipt_context, "continuity": continuity}


@app.post("/v1/attest/complete")
def complete(input: CompleteInput):
    session = latest_session(input.session_id)

    if not session:
        raise HTTPException(status_code=404, detail="session not found")

    if session.get("status") == "complete":
        raise HTTPException(status_code=409, detail="session already complete")

    continuity_receipt_id = session.get("continuity_receipt_id")
    receipt_context = input.receipt_context or session.get("receipt_context") or "real_task"
    sar_payload = dict(input.sar_input)
    sar_payload["continuity_receipt_id"] = continuity_receipt_id
    sar_payload["receipt_context"] = receipt_context
    external_provenance = external_provenance_from_payload(sar_input=sar_payload) or session.get("external_provenance")

    sar = post_json(SAR_URL, sar_payload)
    sar_receipt_id = sar.get("receipt_id")
    if not sar_receipt_id:
        raise HTTPException(status_code=502, detail="settlement-witness receipt_id missing")
    chain_id = sha256_text(continuity_receipt_id + sar_receipt_id)

    completed_session_record = {
        "session_id": input.session_id,
        "status": "complete",
        "receipt_context": receipt_context,
        "continuity_receipt_id": continuity_receipt_id,
        "sar_receipt_id": sar_receipt_id,
        "chain_id": chain_id,
        "completed_at": iso_now(),
    }
    if external_provenance:
        completed_session_record["external_provenance"] = external_provenance
    append_jsonl(SESSION_LEDGER, completed_session_record)
    write_chain(
        chain_id=chain_id,
        agent_id=sar_payload.get("agent_id"),
        activation_id=sar_payload.get("activation_id"),
        continuity_receipt_id=continuity_receipt_id,
        sar_receipt_id=sar_receipt_id,
        stage="chained",
        receipt_context=receipt_context,
        external_provenance=external_provenance,
    )
    write_receipt(
        receipt=sar,
        receipt_type="sar",
        receipt_context=receipt_context,
        chain_id=chain_id,
        external_provenance=external_provenance,
    )

    return {"session_id": input.session_id, "status": "complete", "receipt_context": receipt_context, "sar": sar, "chain_id": chain_id}


@app.get("/v1/attest/session/{session_id}")
def get_session(session_id: str):
    session = latest_session(session_id)

    if not session:
        raise HTTPException(status_code=404, detail="session not found")

    return session


@app.get("/v1/attest/chain/{chain_id}")
def get_chain(chain_id: str):
    return chain_response(chain_id)


@app.get("/v1/attest/receipt/{receipt_id}")
def get_receipt(receipt_id: str):
    receipt = find_receipt(receipt_id)
    if not receipt:
        raise HTTPException(status_code=404, detail="receipt not found")
    return receipt


@app.get("/v1/sar-402/recording/{receipt_id}")
def get_sar402_recording(receipt_id: str):
    """SAR-402 Path B: return the recording-attribution wrapper for a receipt.

    Public, read-only. It returns the stored ``sar402_recording_wrapper_v1``
    envelope for the inner ``receipt_id`` if one exists. It never creates,
    signs, or mutates a wrapper, never touches Path A storage, and never creates
    or requires production key material — it verifies the stored wrapper with the
    configured PUBLIC verification key before returning it.

    A True wrapper here attests to DefaultVerifier's RECORDING act only — not
    delivery, payment execution, access authorization, release control, mainnet
    settlement, or legal finality (see the wrapper's authority_boundary).

    Status codes:
      * 200 — wrapper found and verified;
      * 404 ``receipt not found`` — no Path A receipt and no wrapper for the id;
      * 404 ``no recording wrapper found for receipt`` — Path A receipt exists
        but no Path B wrapper has been recorded;
      * 422 — malformed receipt id;
      * 503 ``recording key unavailable`` — no verification key configured;
      * 500 ``recording wrapper verification failed`` — a stored wrapper failed
        signature/shape verification (a data-integrity fault; never served as
        valid)."""
    if not _is_valid_receipt_id(receipt_id):
        raise HTTPException(status_code=422, detail="invalid receipt id format")

    wrapper = recording_store.get_recording_wrapper(receipt_id)
    if wrapper is None:
        if find_receipt(receipt_id) is not None:
            raise HTTPException(
                status_code=404,
                detail="no recording wrapper found for receipt",
            )
        raise HTTPException(status_code=404, detail="receipt not found")

    public_key = _recording_public_key()
    if public_key is None:
        raise HTTPException(status_code=503, detail="recording key unavailable")

    if not verify_recording_wrapper(wrapper, public_key=public_key):
        raise HTTPException(
            status_code=500, detail="recording wrapper verification failed"
        )

    return {
        "receipt_id": receipt_id,
        "wrapper": wrapper,
        "lookup_path": f"/v1/sar-402/recording/{quote(receipt_id, safe='')}",
        "wrapper_type": wrapper.get("wrapper_type"),
    }


@app.post("/v1/action-commitments")
def post_action_commitment(record: dict):
    """Hosted Path C, Step 1: store a committed Action Commitment record.

    Persists a record whose request/action chain
    (body_digest -> request_digest -> action_ref) is validated and recomputed
    before writing, so a LATER hosted deterministic evaluator can retrieve the
    committed acceptance spec by action_ref instead of trusting a
    caller-submitted spec. This route does NOT evaluate, sign, or prove
    execution / spec satisfaction / release.

    Status codes:
      * 200 — stored (``stored: true`` for a new write, ``stored: false`` for
        an idempotent re-submission of the identical record);
      * 422 — malformed record / digest-chain mismatch;
      * 409 — a different record already exists for the same action_ref."""
    try:
        wrote = commitment_store.store_action_commitment(record)
    except ActionCommitmentConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except ActionCommitmentRecordError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    action_ref = record["action_ref"]
    return {
        "status": "stored",
        "stored": wrote,
        "action_ref": action_ref,
        "lookup_path": f"/v1/action-commitments/{quote(action_ref, safe='')}",
    }


@app.get("/v1/action-commitments/{action_ref}")
def get_action_commitment(action_ref: str):
    """Hosted Path C, Step 1: return the committed Action Commitment record.

    Public, read-only. Returns the stored record for ``action_ref`` so a later
    evaluator can retrieve the committed spec. This route does NOT evaluate
    anything.

    Status codes:
      * 200 — record found;
      * 404 — no record for the action_ref;
      * 422 — malformed action_ref;
      * 500 — a stored record cannot be resolved (data-integrity fault; never
        served as a partial record)."""
    if not commitment_store._is_sha256(action_ref):
        raise HTTPException(status_code=422, detail="invalid action_ref format")

    record = commitment_store.get_action_commitment(action_ref)
    if record is None:
        raise HTTPException(status_code=404, detail="action commitment not found")

    try:
        has_profile = (
            commitment_store.extract_conditional_release_profile(record) is not None
        )
    except Exception as exc:  # pragma: no cover - data-integrity fault
        raise HTTPException(
            status_code=500,
            detail=f"action commitment record could not be resolved: {exc}",
        )

    return {
        "action_ref": action_ref,
        "record": record,
        "has_conditional_release_profile": has_profile,
        "lookup_path": f"/v1/action-commitments/{quote(action_ref, safe='')}",
    }


class DeterministicEvaluateInput(BaseModel):
    """Input for POST /v1/evaluate/deterministic.

    Only ``action_ref`` + ``submitted_output`` are accepted. ``extra=forbid``
    means ANY additional field — including a caller-submitted ``acceptance_spec``
    — is rejected with 422. The committed spec is retrieved server-side by
    ``action_ref`` so the caller cannot substitute the spec at evaluation time."""

    model_config = {"extra": "forbid"}

    action_ref: str
    submitted_output: dict


# Bounded-claim string stamped onto every unsigned Step 2A record so the record
# cannot be mistaken for a signed receipt or a release/execution proof.
_DETERMINISTIC_EVALUATION_BOUNDED_CLAIM = (
    "A deterministic evaluator applied a committed acceptance spec to a "
    "submitted output and produced a recorded result. This record is UNSIGNED: "
    "it is not a Continuity Evaluation Receipt, not a signed receipt, not proof "
    "of execution, not proof of payment or resource-release finality, not an "
    "actual release, and not a statement of objective correctness or legal "
    "sufficiency."
)


@app.post("/v1/evaluate/deterministic")
def post_evaluate_deterministic(input: DeterministicEvaluateInput):
    """Hosted Path C, Step 2A: evaluate a submitted output against the COMMITTED spec.

    The acceptance spec is NEVER taken from the caller — it is retrieved from the
    committed Action Commitment record by ``action_ref`` (covered by
    body_digest -> request_digest -> action_ref), preventing spec substitution.
    The produced record is UNSIGNED (see ``_DETERMINISTIC_EVALUATION_BOUNDED_CLAIM``).

    Status codes:
      * 200 — evaluated and stored (``stored: true`` for a new write,
        ``stored: false`` for an idempotent identical re-submission);
      * 404 — no committed Action Commitment for the action_ref;
      * 422 — malformed action_ref, caller-submitted acceptance_spec / extra
        field, no committed conditional-release profile / acceptance_spec, or a
        bad committed spec shape;
      * 409 — a different evaluation already exists for this action_ref."""
    action_ref = input.action_ref
    if not evaluation_store.is_valid_action_ref(action_ref):
        raise HTTPException(status_code=422, detail="invalid action_ref format")

    commitment = commitment_store.get_action_commitment(action_ref)
    if commitment is None:
        raise HTTPException(status_code=404, detail="action commitment not found")

    profile = commitment_store.extract_conditional_release_profile(commitment)
    if profile is None:
        raise HTTPException(
            status_code=422,
            detail="committed action has no conditional-release profile to evaluate",
        )
    acceptance_spec = profile.get("acceptance_spec")
    if not isinstance(acceptance_spec, dict):
        raise HTTPException(
            status_code=422,
            detail="committed conditional-release profile has no acceptance_spec",
        )

    try:
        outcome = det_evaluator.evaluate_acceptance_spec(
            acceptance_spec, input.submitted_output
        )
    except DeterministicEvaluationError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    release_policy = profile.get("release_policy")
    declared_release_intent = det_evaluator.derive_declared_release_intent(
        outcome["result"], release_policy if isinstance(release_policy, dict) else None
    )

    record = {
        "record_type": evaluation_store.RECORD_TYPE,
        "record_version": evaluation_store.RECORD_VERSION,
        "action_ref": action_ref,
        "spec_id": acceptance_spec.get("spec_id"),
        "evaluator_type": "deterministic",
        "result": outcome["result"],
        "checks": outcome["checks"],
        "declared_release_intent": declared_release_intent,
        "submitted_output": input.submitted_output,
        "bounded_claim": _DETERMINISTIC_EVALUATION_BOUNDED_CLAIM,
    }

    try:
        wrote = evaluation_store.store_deterministic_evaluation(record)
    except DeterministicEvaluationConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except DeterministicEvaluationRecordError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    return {
        "status": "evaluated",
        "stored": wrote,
        "action_ref": action_ref,
        "result": record["result"],
        "declared_release_intent": declared_release_intent,
        "evaluation_lookup_path": f"/v1/evaluate/deterministic/{quote(action_ref, safe='')}",
        "record": record,
    }


@app.get("/v1/evaluate/deterministic/{action_ref}")
def get_evaluate_deterministic(action_ref: str):
    """Hosted Path C, Step 2A: return the stored UNSIGNED evaluation record.

    Public, read-only. Does NOT re-evaluate, does NOT sign.

    Status codes:
      * 200 — evaluation record found;
      * 404 — no evaluation record for the action_ref;
      * 422 — malformed action_ref."""
    if not evaluation_store.is_valid_action_ref(action_ref):
        raise HTTPException(status_code=422, detail="invalid action_ref format")

    record = evaluation_store.get_deterministic_evaluation(action_ref)
    if record is None:
        raise HTTPException(status_code=404, detail="deterministic evaluation not found")

    return {
        "action_ref": action_ref,
        "result": record.get("result"),
        "declared_release_intent": record.get("declared_release_intent"),
        "record": record,
        "evaluation_lookup_path": f"/v1/evaluate/deterministic/{quote(action_ref, safe='')}",
    }


def _continuity_receipt_lookup_path(action_ref: str) -> str:
    return (
        f"/v1/evaluate/deterministic/{quote(action_ref, safe='')}/continuity-receipt"
    )


@app.post("/v1/evaluate/deterministic/{action_ref}/continuity-receipt")
def post_continuity_evaluation_receipt(action_ref: str):
    """Hosted Path C, Step 2B: issue a SIGNED Continuity Evaluation Receipt.

    Takes the already-stored UNSIGNED Step 2A deterministic evaluation record for
    ``action_ref`` and signs a Continuity Evaluation Receipt
    (ds.continuity_evaluation.v0.1) over its evaluation state. The Step 2A record
    is NOT modified, NOT re-evaluated, and remains unsigned. No caller-submitted
    fields are accepted (the route body is empty); ``evaluator_id`` /
    ``policy_ref`` come from config and ``evaluated_at`` is generated fresh at
    signing time (never derived from the Step 2A record).

    Bounded claim: the signed receipt proves only that the named evaluator signed
    the pre-execution evaluation state for the committed action_ref under the
    stated policy_ref. It does NOT prove actual release, payment / resource-
    release finality, execution, objective correctness, or legal sufficiency.

    Status codes:
      * 200 — signed receipt issued (``stored: true`` new, ``stored: false``
        idempotent re-issue of the identical existing receipt);
      * 404 — no Step 2A deterministic evaluation record for the action_ref;
      * 409 — a different signed receipt already exists for this action_ref;
      * 422 — malformed action_ref;
      * 503 — signing key/config missing or invalid (fails safely, no receipt)."""
    if not continuity_receipts.is_valid_action_ref(action_ref):
        raise HTTPException(status_code=422, detail="invalid action_ref format")

    record = evaluation_store.get_deterministic_evaluation(action_ref)
    if record is None:
        raise HTTPException(
            status_code=404,
            detail="deterministic evaluation not found; Step 2A record is required "
            "before a Continuity Evaluation Receipt can be issued",
        )

    # Idempotency: if a signed receipt already exists, return it as a no-op.
    existing = continuity_receipts.get_continuity_evaluation_receipt(action_ref)
    if existing is not None:
        return {
            "status": "continuity_receipt_issued",
            "stored": False,
            "action_ref": action_ref,
            "receipt": existing,
            "receipt_lookup_path": _continuity_receipt_lookup_path(action_ref),
            "bounded_claim": continuity_receipts.BOUNDED_CLAIM,
        }

    # Fail SAFELY if signing key/config is missing — never emit an unsigned/
    # partial receipt.
    try:
        config = continuity_receipts.EvaluatorSigningConfig.from_env()
    except ContinuityReceiptConfigError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    core = continuity_receipts.build_continuity_evaluation_core(
        action_ref=action_ref,
        evaluation_state=record["result"],
        evaluator_id=config.evaluator_id,
        policy_ref=config.policy_ref,
        evaluated_at=continuity_receipts._now_iso_utc(),
    )
    receipt = continuity_receipts.sign_continuity_evaluation_receipt(core, config)

    # Self-verify before storing: a receipt we cannot verify is never persisted.
    try:
        continuity_receipts.verify_continuity_evaluation_receipt(
            receipt, config.public_key_b64
        )
    except ContinuityReceiptVerificationError as exc:  # pragma: no cover - defensive
        raise HTTPException(
            status_code=500,
            detail=f"self-verification failed, refusing to store: {exc}",
        )

    try:
        wrote = continuity_receipts.store_continuity_evaluation_receipt(receipt)
    except ContinuityReceiptConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except ContinuityReceiptError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    return {
        "status": "continuity_receipt_issued",
        "stored": wrote,
        "action_ref": action_ref,
        "receipt": receipt,
        "receipt_lookup_path": _continuity_receipt_lookup_path(action_ref),
        "bounded_claim": continuity_receipts.BOUNDED_CLAIM,
    }


@app.get("/v1/evaluate/deterministic/{action_ref}/continuity-receipt")
def get_continuity_evaluation_receipt(action_ref: str):
    """Hosted Path C, Step 2B: return the stored SIGNED Continuity Evaluation Receipt.

    Public, read-only. Does NOT sign and does NOT auto-issue a receipt on GET.

    Status codes:
      * 200 — signed receipt found;
      * 404 — no signed receipt for the action_ref;
      * 422 — malformed action_ref."""
    if not continuity_receipts.is_valid_action_ref(action_ref):
        raise HTTPException(status_code=422, detail="invalid action_ref format")

    receipt = continuity_receipts.get_continuity_evaluation_receipt(action_ref)
    if receipt is None:
        raise HTTPException(
            status_code=404, detail="continuity evaluation receipt not found"
        )

    return {
        "action_ref": action_ref,
        "receipt": receipt,
        "receipt_lookup_path": _continuity_receipt_lookup_path(action_ref),
        "bounded_claim": continuity_receipts.BOUNDED_CLAIM,
    }


@app.post("/v1/agents/register")
def register_agent(input: RegisterAgentInput):
    agent_id = input.agent_id or "agent:" + uuid4().hex
    existing = latest_agent(agent_id)
    if existing and existing.get("owner_id") != input.owner_id:
        raise HTTPException(status_code=409, detail="agent_id already registered with different owner_id")

    record = registry_record(
        existing,
        agent_id=agent_id,
        owner_id=input.owner_id,
        counterparty=input.counterparty,
        display_name=input.display_name,
        stage=existing.get("activation_stage", "registered") if existing else "registered",
        metadata=input.metadata,
    )
    write_agent(record)
    write_analytics(agent_id=agent_id, activation_id=None, event_type="agent_registered", to_stage=record["activation_stage"])
    return record


@app.get("/v1/agents")
def list_agents(limit: int | None = Query(DEFAULT_LIMIT)):
    records_by_agent: dict[str, dict[str, Any]] = {}
    for record in read_jsonl(AGENT_LEDGER):
        records_by_agent[record["agent_id"]] = record
    agents = sorted_agents(list(records_by_agent.values()), bounded_limit(limit))
    return {"count": len(agents), "agents": agents}


@app.post("/v1/agents/historical-import")
def historical_import_agent(input: HistoricalImportAgentInput):
    if input.activation_type != "historical_import":
        raise HTTPException(
            status_code=400,
            detail={"error": "invalid_activation_type", "reason": "activation_type must be historical_import"},
        )

    if latest_agent(input.agent_id):
        raise HTTPException(status_code=409, detail={"error": "already_registered", "reason": "already_registered"})

    chain_id = input.origin_anchor.get("chain_id")
    if not chain_id:
        raise HTTPException(status_code=400, detail={"error": "missing_origin_anchor_chain_id", "reason": "origin_anchor.chain_id is required"})

    now = iso_now()
    activation_id = "historical_import:" + uuid4().hex
    trustscore_url = f"/trustscore/{input.agent_id}"
    explorer_url = f"/v1/attest/chain/{chain_id}"
    external_provenance = external_provenance_from_payload(origin_anchor=input.origin_anchor, lineage=input.lineage)

    registry = {
        "agent_id": input.agent_id,
        "display_name": input.display_name,
        "registered_at": now,
        "created_at": now,
        "updated_at": now,
        "last_seen_at": now,
        "activation_stage": "chained",
        "stage": "chained",
        "status": "chained",
        "activation_type": "historical_import",
        "activation_receipt_id": chain_id,
        "latest_activation_id": activation_id,
        "origin_anchor": input.origin_anchor,
        "lineage": input.lineage,
        "receipt_ids": [],
        "real_receipt_ids": [],
        "chain_ids": [chain_id],
        "latest_chain_id": chain_id,
        "explorer_url": explorer_url,
        "trustscore_url": trustscore_url,
        "metadata": input.metadata,
    }
    write_agent(registry)

    activation_record = {
        "activation_id": activation_id,
        "agent_id": input.agent_id,
        "activation_type": "historical_import",
        "stage": "chained",
        "activation_stage": "chained",
        "status": "chained",
        "origin_anchor": input.origin_anchor,
        "lineage": input.lineage,
        "chain_id": chain_id,
        "created_at": now,
        "updated_at": now,
        "metadata": input.metadata,
    }
    if external_provenance:
        registry["external_provenance"] = external_provenance
        activation_record["external_provenance"] = external_provenance
    append_jsonl(ACTIVATION_LEDGER, activation_record)

    legacy_subjects = input.lineage.get("legacy_subjects") or []
    write_analytics(
        agent_id=input.agent_id,
        activation_id=activation_id,
        event_type="historical_import",
        from_stage="legacy_detected" if legacy_subjects else None,
        to_stage="chained",
        metadata={
            "origin_anchor": input.origin_anchor,
            "lineage": input.lineage,
            "chain_id": chain_id,
        },
    )

    return {"activation_id": activation_id, "agent_id": input.agent_id, "stage": "chained", "status": "chained", "registry": registry}


@app.get("/v1/agents/{agent_id}")
def get_agent(agent_id: str):
    agent = latest_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="agent not found")
    return agent


@app.post("/v1/agents/{agent_id}/activate")
def activate_agent(agent_id: str, input: ActivateAgentInput):
    t0 = time.perf_counter()
    agent = latest_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="agent not found")

    activation_id = "activation:" + uuid4().hex
    activated_agent = registry_record(
        agent,
        agent_id=agent_id,
        owner_id=agent["owner_id"],
        counterparty=agent["counterparty"],
        display_name=agent.get("display_name"),
        stage="activated",
        metadata=agent.get("metadata", {}),
        latest_activation_id=activation_id,
    )
    continuity: dict[str, Any] | None = None
    sar: dict[str, Any] | None = None
    continuity_receipt_id: str | None = None
    sar_receipt_id: str | None = None

    try:
        continuity_input = activation_continuity_input(input.continuity_input, agent_id)
        continuity = post_json(CONTINUITY_EVALUATE_URL, continuity_input)
        continuity_receipt_id = continuity.get("receipt_id")
        if not continuity_receipt_id:
            raise HTTPException(status_code=502, detail="continuity receipt_id missing")

        sar_claim = activation_sar_claim(
            agent_id=agent_id,
            activation_id=activation_id,
            receipt_context=input.receipt_context,
            continuity_receipt_id=continuity_receipt_id,
            activation_spec=input.activation_spec,
            activation_output=input.activation_output,
        )
        sar_spec = sar_claim if input.receipt_context == "activation_demo" else input.activation_spec
        sar_output = dict(sar_claim) if input.receipt_context == "activation_demo" else input.activation_output
        sar_payload = {
            "task_id": activation_id,
            "spec": sar_spec,
            "output": sar_output,
            "counterparty": agent["counterparty"],
            "agent_id": agent_id,
            "activation_id": activation_id,
            "receipt_context": input.receipt_context,
            "continuity_receipt_id": continuity_receipt_id,
        }
        external_provenance = external_provenance_from_payload(sar_input=sar_payload, continuity_input=continuity_input)
        sar = post_json(SAR_URL, sar_payload)
        sar_receipt_id = sar.get("receipt_id")
        if not sar_receipt_id:
            raise HTTPException(status_code=502, detail="settlement-witness receipt_id missing")
    except HTTPException as exc:
        elapsed_ms = int((time.perf_counter() - t0) * 1000)
        record_failed_activation(
            agent=agent,
            agent_id=agent_id,
            activation_id=activation_id,
            receipt_context=input.receipt_context,
            metadata=input.metadata,
            error=exc.detail,
            continuity_receipt_id=continuity_receipt_id,
            sar_receipt_id=sar_receipt_id,
            elapsed_ms=elapsed_ms,
        )
        raise HTTPException(
            status_code=exc.status_code,
            detail={
                "activation_id": activation_id,
                "agent_id": agent_id,
                "status": "failed",
                "error": exc.detail,
            },
        )
    except Exception as exc:
        elapsed_ms = int((time.perf_counter() - t0) * 1000)
        record_failed_activation(
            agent=agent,
            agent_id=agent_id,
            activation_id=activation_id,
            receipt_context=input.receipt_context,
            metadata=input.metadata,
            error=str(exc),
            continuity_receipt_id=continuity_receipt_id,
            sar_receipt_id=sar_receipt_id,
            elapsed_ms=elapsed_ms,
        )
        raise HTTPException(
            status_code=502,
            detail={
                "activation_id": activation_id,
                "agent_id": agent_id,
                "status": "failed",
                "error": str(exc),
            },
        )

    sar_verdict = sar_verdict_value(sar)
    sar_reason = sar_reason_code(sar)
    if not is_sar_pass(sar):
        elapsed_ms = int((time.perf_counter() - t0) * 1000)
        record_failed_activation(
            agent=agent,
            agent_id=agent_id,
            activation_id=activation_id,
            receipt_context=input.receipt_context,
            metadata=input.metadata,
            error=sar_reason or "SAR verdict did not pass",
            continuity_receipt_id=continuity_receipt_id,
            sar_receipt_id=sar_receipt_id,
            sar_verdict=sar_verdict,
            reason_code=sar_reason,
            elapsed_ms=elapsed_ms,
        )
        write_receipt(
            receipt=continuity,
            receipt_type="continuity",
            receipt_context=input.receipt_context,
            agent_id=agent_id,
            activation_id=activation_id,
        )
        write_receipt(
            receipt=sar,
            receipt_type="sar",
            receipt_context=input.receipt_context,
            agent_id=agent_id,
            activation_id=activation_id,
            external_provenance=external_provenance,
        )
        return {
            "activation_id": activation_id,
            "agent_id": agent_id,
            "stage": "activation_failed",
            "receipt_context": input.receipt_context,
            "status": "failed",
            "elapsed_ms": elapsed_ms,
            "continuity": continuity,
            "sar": sar,
            "sar_verdict": sar_verdict,
            "reason_code": sar_reason,
            "chain": None,
            "registry": {
                "agent_id": agent_id,
                "stage": "activation_failed",
                "activation_stage": "activation_failed",
                "status": "activation_failed",
                "latest_activation_id": activation_id,
                "latest_chain_id": agent.get("latest_chain_id"),
                "latest_sar_receipt_id": sar_receipt_id,
            },
        }

    verified_agent = registry_record(
        activated_agent,
        agent_id=agent_id,
        owner_id=agent["owner_id"],
        counterparty=agent["counterparty"],
        display_name=agent.get("display_name"),
        stage="verified",
        metadata=agent.get("metadata", {}),
        latest_activation_id=activation_id,
        latest_continuity_receipt_id=continuity_receipt_id,
        latest_sar_receipt_id=sar_receipt_id,
    )
    write_analytics(
        agent_id=agent_id,
        activation_id=activation_id,
        event_type="stage_changed",
        receipt_context=input.receipt_context,
        from_stage="activated",
        to_stage="verified",
        metadata={"sar_verdict": sar_verdict},
    )

    chain_id = sha256_text(continuity_receipt_id + sar_receipt_id)
    chain = chain_lookup(chain_id)
    write_chain(
        chain_id=chain_id,
        agent_id=agent_id,
        activation_id=activation_id,
        continuity_receipt_id=continuity_receipt_id,
        sar_receipt_id=sar_receipt_id,
        sar_verdict=sar_verdict,
        stage="chained",
        receipt_context=input.receipt_context,
        external_provenance=external_provenance,
    )
    if external_provenance:
        chain = {**chain, "external_provenance": external_provenance}
    chained_agent = registry_record(
        verified_agent,
        agent_id=agent_id,
        owner_id=agent["owner_id"],
        counterparty=agent["counterparty"],
        display_name=agent.get("display_name"),
        stage="chained",
        metadata=agent.get("metadata", {}),
        latest_activation_id=activation_id,
        latest_chain_id=chain_id,
        latest_continuity_receipt_id=continuity_receipt_id,
        latest_sar_receipt_id=sar_receipt_id,
    )

    now = iso_now()
    activation_record = {
        "activation_id": activation_id,
        "agent_id": agent_id,
        "stage": "chained",
        "activation_stage": "chained",
        "status": "complete",
        "receipt_context": input.receipt_context,
        "continuity_receipt_id": continuity_receipt_id,
        "sar_receipt_id": sar_receipt_id,
        "sar_verdict": sar_verdict,
        "chain_id": chain_id,
        "created_at": now,
        "updated_at": now,
        "metadata": input.metadata,
    }
    if external_provenance:
        activation_record["external_provenance"] = external_provenance
    append_jsonl(ACTIVATION_LEDGER, activation_record)
    write_receipt(
        receipt=continuity,
        receipt_type="continuity",
        receipt_context=input.receipt_context,
        agent_id=agent_id,
        activation_id=activation_id,
        chain_id=chain_id,
    )
    write_receipt(
        receipt=sar,
        receipt_type="sar",
        receipt_context=input.receipt_context,
        agent_id=agent_id,
        activation_id=activation_id,
        chain_id=chain_id,
        external_provenance=external_provenance,
    )
    write_agent(chained_agent)
    elapsed_ms = int((time.perf_counter() - t0) * 1000)
    write_analytics(
        agent_id=agent_id,
        activation_id=activation_id,
        event_type="stage_changed",
        receipt_context=input.receipt_context,
        from_stage="verified",
        to_stage="chained",
        elapsed_ms=elapsed_ms,
        metadata={"sar_verdict": sar_verdict},
    )

    return {
        "activation_id": activation_id,
        "agent_id": agent_id,
        "stage": "chained",
        "receipt_context": input.receipt_context,
        "status": "complete",
        "elapsed_ms": elapsed_ms,
        "continuity": continuity,
        "sar": sar,
        "sar_verdict": sar_verdict,
        "chain": chain,
        "registry": {
            "agent_id": agent_id,
            "stage": "chained",
            "activation_stage": "chained",
            "latest_activation_id": activation_id,
            "latest_chain_id": chain_id,
            "latest_sar_receipt_id": sar_receipt_id,
        },
    }

@app.post("/v1/agents/{agent_id}/continuity")
def record_continuity_pair(agent_id: str, input: ContinuityPairInput):
    agent = latest_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="agent not found")
    if not stage_at_least(agent.get("activation_stage", "registered"), "verified"):
        raise HTTPException(status_code=409, detail="agent must be verified or chained before continuity can be recorded")

    continuity_input = activation_continuity_input(input.continuity_input, agent_id)
    continuity = post_json(CONTINUITY_EVALUATE_URL, continuity_input)
    continuity_receipt_id = continuity.get("receipt_id")
    if not continuity_receipt_id:
        raise HTTPException(status_code=502, detail="continuity receipt_id missing")

    activation_id = input.previous_activation_id or agent.get("latest_activation_id")
    existing_activation = latest_activation(activation_id) if activation_id else None
    existing_activation = existing_activation or {}
    sar_receipt_id = existing_activation.get("sar_receipt_id") or agent.get("latest_sar_receipt_id")
    if not sar_receipt_id:
        raise HTTPException(status_code=409, detail="agent must have existing sar_receipt_id before continuity can be chained")

    chain_id = sha256_text(continuity_receipt_id + sar_receipt_id)
    chain_created_at = iso_now()
    sar_receipt_record = latest_receipt(sar_receipt_id) or {}
    sar_receipt = sar_receipt_record.get("receipt") or {}
    continuity_classification = first_present(continuity, ["continuity_classification", "classification", "verdict", "status"])
    sar_verdict = first_present(sar_receipt, ["verdict", "status", "result"])
    predicate_status_vector = first_present(continuity, ["predicate_status_vector", "predicate_status", "predicates"])
    external_provenance = (
        existing_activation.get("external_provenance")
        or sar_receipt_record.get("external_provenance")
        or external_provenance_from_payload(sar_input=sar_receipt, continuity_input=continuity_input)
    )
    write_chain(
        chain_id=chain_id,
        agent_id=agent_id,
        activation_id=activation_id,
        continuity_receipt_id=continuity_receipt_id,
        sar_receipt_id=sar_receipt_id,
        time_delta_seconds=seconds_between(existing_activation.get("updated_at") or existing_activation.get("created_at"), chain_created_at),
        continuity_classification=continuity_classification,
        sar_verdict=sar_verdict,
        verdict_correlation=verdict_correlation(continuity_classification, sar_verdict),
        predicate_status_vector=predicate_status_vector,
        stage="continuous",
        receipt_context="continuity_pair",
        external_provenance=external_provenance,
    )

    continuous_agent = registry_record(
        agent,
        agent_id=agent_id,
        owner_id=agent["owner_id"],
        counterparty=agent["counterparty"],
        display_name=agent.get("display_name"),
        stage="continuous",
        metadata=agent.get("metadata", {}),
        latest_activation_id=activation_id,
        latest_chain_id=chain_id,
        latest_continuity_receipt_id=continuity_receipt_id,
        latest_sar_receipt_id=sar_receipt_id,
    )
    write_agent(continuous_agent)

    if activation_id:
        updated_activation = {
            **existing_activation,
            "activation_id": activation_id,
            "agent_id": agent_id,
            "stage": "continuous",
            "activation_stage": "continuous",
            "receipt_context": "continuity_pair",
            "continuity_pair_receipt_id": continuity_receipt_id,
            "sar_receipt_id": sar_receipt_id,
            "chain_id": chain_id,
            "created_at": existing_activation.get("created_at") or chain_created_at,
            "updated_at": chain_created_at,
            "metadata": {**existing_activation.get("metadata", {}), **input.metadata},
        }
        if external_provenance:
            updated_activation["external_provenance"] = external_provenance
        append_jsonl(ACTIVATION_LEDGER, updated_activation)

    write_receipt(
        receipt=continuity,
        receipt_type="continuity",
        receipt_context="continuity_pair",
        agent_id=agent_id,
        activation_id=activation_id,
        chain_id=chain_id,
    )
    write_analytics(
        agent_id=agent_id,
        activation_id=activation_id,
        event_type="stage_changed",
        receipt_context="continuity_pair",
        from_stage=agent.get("activation_stage"),
        to_stage="continuous",
    )

    return {
        "agent_id": agent_id,
        "activation_id": activation_id,
        "stage": "continuous",
        "receipt_context": "continuity_pair",
        "continuity": continuity,
        "previous_chain_id": input.previous_chain_id,
        "chain_id": chain_id,
        "sar_receipt_id": sar_receipt_id,
        "continuity_receipt_id": continuity_receipt_id,
        "registry": {
            "agent_id": agent_id,
            "stage": "continuous",
            "activation_stage": "continuous",
            "latest_activation_id": activation_id,
            "latest_chain_id": continuous_agent.get("latest_chain_id"),
            "latest_continuity_receipt_id": continuity_receipt_id,
        },
    }


@app.get("/v1/agents/{agent_id}/activations")
def list_agent_activations(agent_id: str, limit: int | None = Query(DEFAULT_LIMIT), stage: str | None = None, receipt_context: str | None = None):
    if not latest_agent(agent_id):
        raise HTTPException(status_code=404, detail="agent not found")
    if stage and stage not in STAGE_ORDER:
        raise HTTPException(status_code=400, detail="invalid stage filter")
    if receipt_context and receipt_context not in set(get_args(ReceiptContext)):
        raise HTTPException(status_code=400, detail="invalid receipt_context filter")

    activations_by_id: dict[str, dict[str, Any]] = {}
    for record in read_jsonl(ACTIVATION_LEDGER):
        if record.get("agent_id") != agent_id:
            continue
        if stage and record.get("stage") != stage and record.get("activation_stage") != stage:
            continue
        if receipt_context and record.get("receipt_context") != receipt_context:
            continue
        activations_by_id[record["activation_id"]] = record
    activations = sorted_recent(list(activations_by_id.values()), "created_at", bounded_limit(limit))
    return {"agent_id": agent_id, "count": len(activations), "activations": activations}


@app.get("/v1/activation/{activation_id}")
def get_activation(activation_id: str):
    activation = latest_activation(activation_id)
    if not activation:
        raise HTTPException(status_code=404, detail="activation not found")
    events = [event for event in read_jsonl(ANALYTICS_LEDGER) if event.get("activation_id") == activation_id]
    return {**activation, "events": sorted_recent(events, "occurred_at", MAX_LIMIT)}


@app.get("/v1/chains")
def list_chains(agent_id: str | None = None, limit: int | None = Query(DEFAULT_LIMIT)):
    chains = read_jsonl(CHAIN_LEDGER)
    if agent_id:
        chains = [chain for chain in chains if chain.get("agent_id") == agent_id]
    chains = sorted_recent(chains, "created_at", bounded_limit(limit))
    return {"count": len(chains), "chains": chains}


@app.get("/v1/receipts")
def list_receipts(agent_id: str | None = None, limit: int | None = Query(DEFAULT_LIMIT)):
    receipts = read_jsonl(RECEIPT_LEDGER)
    if agent_id:
        receipts = [receipt for receipt in receipts if receipt.get("agent_id") == agent_id]
    receipts = sorted_recent(receipts, "created_at", bounded_limit(limit))
    return {"count": len(receipts), "receipts": receipts}


@app.get("/v1/agents/{agent_id}/summary")
def get_agent_summary(agent_id: str, limit: int | None = Query(DEFAULT_LIMIT)):
    agent = latest_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="agent not found")

    actual_limit = bounded_limit(limit)
    activations = list_agent_activations(agent_id, limit=actual_limit)["activations"]
    chains = list_chains(agent_id=agent_id, limit=actual_limit)["chains"]
    receipts = list_receipts(agent_id=agent_id, limit=actual_limit)["receipts"]
    all_activations_by_id: dict[str, dict[str, Any]] = {}
    for record in read_jsonl(ACTIVATION_LEDGER):
        if record.get("agent_id") == agent_id:
            all_activations_by_id[record["activation_id"]] = record
    all_chains = [record for record in read_jsonl(CHAIN_LEDGER) if record.get("agent_id") == agent_id]
    all_receipts = [record for record in read_jsonl(RECEIPT_LEDGER) if record.get("agent_id") == agent_id]
    evidence_receipt_ids = {record.get("receipt_id") for record in all_receipts if record.get("receipt_id")}
    for chain in all_chains:
        for receipt_field in ("continuity_receipt_id", "sar_receipt_id"):
            receipt_id = chain.get(receipt_field)
            if receipt_id:
                evidence_receipt_ids.add(receipt_id)
    latest_chain = max(
        (chain for chain in all_chains if chain.get("created_at")),
        key=lambda chain: chain["created_at"],
        default=None,
    )
    latest_receipt_ids = None
    if latest_chain:
        latest_receipt_ids = {
            receipt_field: latest_chain[receipt_field]
            for receipt_field in ("continuity_receipt_id", "sar_receipt_id")
            if latest_chain.get(receipt_field)
        }
    provenance_records = [
        record
        for record in all_chains + list(all_activations_by_id.values()) + all_receipts + [agent]
        if record.get("external_provenance")
    ]
    latest_external_provenance_record = max(
        provenance_records,
        key=lambda record: record.get("updated_at") or record.get("created_at") or "",
        default=None,
    )
    latest_dates = [
        value
        for value in [agent.get("updated_at")]
        + [item.get("updated_at") or item.get("created_at") for item in all_activations_by_id.values()]
        + [item.get("created_at") for item in all_chains]
        + [item.get("created_at") for item in all_receipts]
        if value
    ]
    trustscore_url = f"/trustscore/{agent_id}"
    badge_url = f"/badge/{agent_id}.svg"
    trustscore_v1 = fetch_trustscore(agent_id)
    evidence_summary = {
        "receipt_count": len(evidence_receipt_ids),
        "chain_count": len(all_chains),
        "activation_count": len(all_activations_by_id),
        "latest_activity_at": max(latest_dates) if latest_dates else None,
        "latest_chain_id": latest_chain.get("chain_id") if latest_chain else None,
        "latest_receipt_ids": latest_receipt_ids,
    }
    if latest_external_provenance_record:
        evidence_summary["external_provenance_count"] = len(provenance_records)
        evidence_summary["latest_external_provenance"] = latest_external_provenance_record["external_provenance"]

    return {
        "agent": agent,
        "activations": activations,
        "chains": chains,
        "receipts": receipts,
        "evidence_summary": evidence_summary,
        "trustscore_v1": trustscore_v1,
        "trustscore_url": trustscore_url,
        "badge_url": badge_url,
        "badge_markdown": build_badge_markdown(agent_id),
    }


@app.get("/v1/explorer/metrics")
def explorer_metrics():
    agents_by_id: dict[str, dict[str, Any]] = {}
    for record in read_jsonl(AGENT_LEDGER):
        agents_by_id[record["agent_id"]] = record
    agents = list(agents_by_id.values())
    activation_records_by_id: dict[str, dict[str, Any]] = {}
    for record in read_jsonl(ACTIVATION_LEDGER):
        activation_id = record.get("activation_id")
        if activation_id:
            activation_records_by_id[activation_id] = record
    activation_records = list(activation_records_by_id.values())
    activation_success_total = sum(1 for record in activation_records if stage_at_least(record.get("activation_stage") or record.get("stage", "registered"), "verified") and record.get("status") != "failed")
    activation_failed_total = sum(1 for record in activation_records if record.get("status") == "failed" or record.get("status") == "activation_failed")
    activation_attempts_total = len(activation_records)
    verified_agents_total = sum(1 for agent in agents if stage_at_least(agent.get("activation_stage", "registered"), "verified") and agent.get("status") != "activation_failed")
    chain_ids = {chain.get("chain_id") for chain in read_jsonl(CHAIN_LEDGER) if chain.get("chain_id")}
    activation_success_rate = activation_success_total / activation_attempts_total if activation_attempts_total else 0
    return {
        "registered_agents_total": len(agents),
        "activation_attempts_total": activation_attempts_total,
        "activation_success_total": activation_success_total,
        "activation_failed_total": activation_failed_total,
        "activation_success_rate": activation_success_rate,
        "verified_agents_total": verified_agents_total,
        "chains_total": len(chain_ids),
        "activated_agents_total": activation_attempts_total,
        "activation_conversion_rate": activation_success_rate,
        "generated_at": iso_now(),
    }
