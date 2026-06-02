from __future__ import annotations

import copy
import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
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

CONTINUITY_EVALUATE_URL = "http://127.0.0.1:3002/continuity/evaluate"
CONTINUITY_CHAIN_URL = "http://127.0.0.1:3002/continuity/chain"
SAR_URL = "http://127.0.0.1:3001/settlement-witness"

HTTP_TIMEOUT_SECONDS = 15
DEFAULT_LIMIT = 50
MAX_LIMIT = 200

ActivationStage = Literal["registered", "activated", "activation_failed", "verified", "chained", "continuous"]
ReceiptContext = Literal["activation_demo", "real_task", "continuity_pair"]

STAGE_ORDER = {
    "registered": 0,
    "activation_failed": 0,
    "activated": 1,
    "verified": 2,
    "chained": 3,
    "continuous": 4,
}

app = FastAPI(title=SERVICE, version=VERSION)


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
) -> None:
    receipt_id = receipt.get("receipt_id")
    if not receipt_id:
        return
    append_jsonl(
        RECEIPT_LEDGER,
        {
            "receipt_id": receipt_id,
            "receipt_type": receipt_type,
            "receipt_context": receipt_context,
            "agent_id": agent_id,
            "activation_id": activation_id,
            "chain_id": chain_id,
            "created_at": iso_now(),
            "receipt": receipt,
        },
    )


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
    append_jsonl(CHAIN_LEDGER, record)
    return record


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
    return payload


def first_present(record: dict[str, Any], keys: list[str]) -> Any:
    for key in keys:
        value = record.get(key)
        if value is not None:
            return value
    return None


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
    )
    write_receipt(receipt=continuity, receipt_type="continuity", receipt_context=input.receipt_context, chain_id=chain_id)
    write_receipt(receipt=sar, receipt_type="sar", receipt_context=input.receipt_context, chain_id=chain_id)

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

    if not continuity_receipt_id:
        raise HTTPException(status_code=502, detail="continuity receipt_id missing")

    session_id = "attest_session:" + uuid4().hex

    append_jsonl(
        SESSION_LEDGER,
        {
            "session_id": session_id,
            "status": "pending",
            "receipt_context": input.receipt_context,
            "continuity_receipt_id": continuity_receipt_id,
            "metadata": input.metadata,
            "created_at": iso_now(),
        },
    )
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

    sar = post_json(SAR_URL, sar_payload)
    sar_receipt_id = sar.get("receipt_id")
    if not sar_receipt_id:
        raise HTTPException(status_code=502, detail="settlement-witness receipt_id missing")
    chain_id = sha256_text(continuity_receipt_id + sar_receipt_id)

    append_jsonl(
        SESSION_LEDGER,
        {
            "session_id": input.session_id,
            "status": "complete",
            "receipt_context": receipt_context,
            "continuity_receipt_id": continuity_receipt_id,
            "sar_receipt_id": sar_receipt_id,
            "chain_id": chain_id,
            "completed_at": iso_now(),
        },
    )
    write_chain(
        chain_id=chain_id,
        agent_id=sar_payload.get("agent_id"),
        activation_id=sar_payload.get("activation_id"),
        continuity_receipt_id=continuity_receipt_id,
        sar_receipt_id=sar_receipt_id,
        stage="chained",
        receipt_context=receipt_context,
    )
    write_receipt(receipt=sar, receipt_type="sar", receipt_context=receipt_context, chain_id=chain_id)

    return {"session_id": input.session_id, "status": "complete", "receipt_context": receipt_context, "sar": sar, "chain_id": chain_id}


@app.get("/v1/attest/session/{session_id}")
def get_session(session_id: str):
    session = latest_session(session_id)

    if not session:
        raise HTTPException(status_code=404, detail="session not found")

    return session


@app.get("/v1/attest/chain/{chain_id}")
def get_chain(chain_id: str):
    return get_json(f"{CONTINUITY_CHAIN_URL}/{chain_id}")


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
    )
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
    if receipt_context and receipt_context not in {"activation_demo", "real_task", "continuity_pair"}:
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
    return {
        "agent": agent,
        "activations": activations,
        "chains": chains,
        "receipts": receipts,
        "evidence_summary": {
            "receipt_count": len(all_receipts),
            "chain_count": len(all_chains),
            "activation_count": len(all_activations_by_id),
            "latest_activity_at": max(latest_dates) if latest_dates else None,
        },
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
