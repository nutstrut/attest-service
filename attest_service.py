from __future__ import annotations

import fcntl
import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import requests
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

SERVICE = "attest-service"
VERSION = "0.1"

BASE_DIR = Path(__file__).resolve().parent
SESSION_LEDGER = BASE_DIR / "attest_sessions_master.jsonl"

CONTINUITY_EVALUATE_URL = "http://127.0.0.1:3002/continuity/evaluate"
CONTINUITY_CHAIN_URL = "http://127.0.0.1:3002/continuity/chain"
SAR_URL = "http://127.0.0.1:3001/settlement-witness"

HTTP_TIMEOUT_SECONDS = 15

app = FastAPI(title=SERVICE, version=VERSION)

def iso_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def append_jsonl(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            f.write(json.dumps(record, separators=(",", ":"), ensure_ascii=False) + "\n")
            f.flush()
        finally:
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


def latest_session(session_id: str) -> dict[str, Any] | None:
    latest = None
    for rec in read_jsonl(SESSION_LEDGER):
        if rec.get("session_id") == session_id:
            latest = rec
    return latest

def post_json(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    resp = requests.post(url, json=payload, timeout=HTTP_TIMEOUT_SECONDS)
    data = resp.json()
    if resp.status_code >= 400:
        raise HTTPException(status_code=502, detail=data)
    return data


def get_json(url: str) -> dict[str, Any]:
    resp = requests.get(url, timeout=HTTP_TIMEOUT_SECONDS)
    data = resp.json()
    if resp.status_code >= 400:
        raise HTTPException(status_code=502, detail=data)
    return data

class SyncAttestInput(BaseModel):
    continuity_input: dict[str, Any]
    sar_input: dict[str, Any]


class BeginInput(BaseModel):
    continuity_input: dict[str, Any]
    metadata: dict[str, Any] = Field(default_factory=dict)


class CompleteInput(BaseModel):
    session_id: str
    sar_input: dict[str, Any]


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
    sar = post_json(SAR_URL, sar_payload)
    sar_receipt_id = sar.get("receipt_id")

    chain_id = sha256_text(continuity_receipt_id + sar_receipt_id)

    try:
        chain = get_json(f"{CONTINUITY_CHAIN_URL}/{chain_id}")
    except Exception:
        chain = {"chain_id": chain_id, "chain_status": "lookup_unavailable"}

    return {
        "service": SERVICE,
        "version": VERSION,
        "mode": "sync",
        "status": "complete",
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

    append_jsonl(SESSION_LEDGER, {
        "session_id": session_id,
        "status": "pending",
        "continuity_receipt_id": continuity_receipt_id,
        "created_at": iso_now()
    })

    return {
        "session_id": session_id,
        "status": "pending",
        "continuity": continuity
    }

@app.post("/v1/attest/complete")
def complete(input: CompleteInput):
    session = latest_session(input.session_id)

    if not session:
        raise HTTPException(status_code=404, detail="session not found")

    if session.get("status") == "complete":
        raise HTTPException(status_code=409, detail="session already complete")

    continuity_receipt_id = session.get("continuity_receipt_id")
    sar_payload = dict(input.sar_input)
    sar_payload["continuity_receipt_id"] = continuity_receipt_id

    sar = post_json(SAR_URL, sar_payload)
    sar_receipt_id = sar.get("receipt_id")
    chain_id = sha256_text(continuity_receipt_id + sar_receipt_id)

    append_jsonl(SESSION_LEDGER, {
        "session_id": input.session_id,
        "status": "complete",
        "continuity_receipt_id": continuity_receipt_id,
        "sar_receipt_id": sar_receipt_id,
        "chain_id": chain_id,
        "completed_at": iso_now()
    })

    return {
        "session_id": input.session_id,
        "status": "complete",
        "sar": sar,
        "chain_id": chain_id
    }

@app.get("/v1/attest/session/{session_id}")
def get_session(session_id: str):
    session = latest_session(session_id)

    if not session:
        raise HTTPException(status_code=404, detail="session not found")

    return session


@app.get("/v1/attest/chain/{chain_id}")
def get_chain(chain_id: str):
    return get_json(f"{CONTINUITY_CHAIN_URL}/{chain_id}")
