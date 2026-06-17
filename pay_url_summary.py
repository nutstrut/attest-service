"""Controlled `/pay/url-summary` SAR-402 demo loop — demo + live x402 evidence.

This module wires an x402-style paid URL-summary action to the *committed,
authoritative* SAR-402 builder/validator/ingestion layer living in
`/home/ubuntu/morpheus`. It does NOT hand-write receipts and it does NOT define a
new schema. It:

    1. accepts a controlled URL-summary request (a `url` to fetch, or inline
       `text` for a fully network-free run),
    2. produces *deterministic* delivery evidence for the requested action
       (requested_url, resolved_url, status_code, title, word_count,
       content_sha256, a short deterministic excerpt, delivered_at, and a
       delivery_evidence_digest binding all of it),
    3. builds the payment leg in one of two explicit modes:
         * `x402_demo` — the existing controlled demo/test evidence, or
         * `x402_live` — real, facilitator-verified x402 payment evidence
           (see `x402_live.py`),
    4. normalizes payment + delivery evidence into the committed demo ingestion
       shape (`morpheus.sar402_agent.normalize_demo`),
    5. calls the committed Morpheus SAR-402 ingestion/runner
       (`run_evidence_doc`), which builds via the committed builder and
       re-validates via the committed validator,
    6. preserves source evidence, normalized view, receipt, and a run report
       locally under `reports/sar402-demo/runs/`,
    7. returns enough to inspect/link the generated receipt — with the payment
       mode visible in the request, evidence doc, SAR-402 payment block, the
       preserved report metadata, and the HTTP response.

Authority boundary (non-negotiable): the verifier never holds execution
authority. This endpoint performs the (controlled) delivery and *records* the
result through SAR-402; SAR-402 does not gate, release, or move anything. In
gate mode an external, non-forbidden `gate_controller` is named — never the
verifier / Default Settlement / Morpheus / SettlementWitness / SAR-402 itself.

Payment evidence honesty: `x402_demo` is explicitly demo-marked and is never
labelled as a real on-chain settlement. `x402_live` only ever produces a
`verified` receipt *after* a real x402 facilitator verification (and, in record
mode, settlement) succeeds — otherwise it fails cleanly and produces no receipt.
Live mode never silently falls back to demo evidence. See
`reports/sar402-demo/real-x402-payment-evidence-report-v0.1.md`.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import requests
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Make the committed Morpheus SAR-402 package importable (authoritative source).
# ---------------------------------------------------------------------------

MORPHEUS_ROOT = Path(os.environ.get("MORPHEUS_ROOT", "/home/ubuntu/morpheus"))
if str(MORPHEUS_ROOT) not in sys.path:
    sys.path.insert(0, str(MORPHEUS_ROOT))

# The committed ingestion layer is authoritative. We feed evidence into it; we
# never bypass it by hand-writing or hand-validating receipts.
from morpheus.sar402_agent import EvidenceError, run_evidence_doc  # noqa: E402

# Live x402 boundary (config validation + facilitator verify/settle adapter).
from x402_live import (  # noqa: E402
    MODE_DEMO,
    MODE_LIVE,
    FacilitatorClient,
    X402ConfigError,
    X402VerificationError,
    build_live_x402_block,
    load_x402_config,
    verify_and_settle,
)

BASE_DIR = Path(__file__).resolve().parent
DEMO_RUNS_DIR = BASE_DIR / "reports" / "sar402-demo" / "runs"

# Controlled, honestly-labelled demo payment context. These are NOT real
# wallets/transactions; the prefixes make the demo nature visible inside the
# generated receipt's payment block.
DEMO_NETWORK = "eip155:8453"  # Base (CAIP-2); chain-agnostic field, demo value.
DEMO_PAY_TO = "0xDEMO0000000000000000000000000000000PAYTO"
DEMO_PAYER = "0xDEMO00000000000000000000000000000PAYER"
DEMO_PRICE_VALUE = "1000"  # 0.001 of a 6-decimals asset
DEMO_PRICE_CURRENCY = "USDC"
DEMO_PRICE_DECIMALS = 6
DEMO_ISSUER_AGENT = "agent:attest-service:pay-url-summary-demo"
QUOTE_WINDOW_SECONDS = 600

USER_AGENT = "attest-service-pay-url-summary/0.1 (+sar-402 controlled demo)"
FETCH_TIMEOUT_SECONDS = 15
EXCERPT_CHARS = 280

router = APIRouter()


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class UrlSummaryInput(BaseModel):
    url: Optional[str] = Field(
        default=None,
        description="URL to fetch and summarize. Mutually sufficient with `text`.",
    )
    text: Optional[str] = Field(
        default=None,
        description="Inline text to summarize instead of fetching a URL "
        "(fully network-free, deterministic).",
    )
    title: Optional[str] = Field(
        default=None,
        description="Optional title override (mainly for inline `text` mode).",
    )
    mode: str = Field(
        default="record",
        description="SAR-402 ingestion mode: 'record' (post-delivery, full "
        "loop) or 'gate' (payment-verified pre-delivery proof).",
    )
    gate_controller: Optional[str] = Field(
        default=None,
        description="Gate mode only: the external system that controls release. "
        "Never the verifier/Morpheus/SettlementWitness/SAR-402.",
    )
    release_policy: Optional[str] = Field(
        default=None,
        description="Gate mode only: explicit release policy string.",
    )
    payment_mode: Optional[str] = Field(
        default=None,
        description="Payment evidence mode: 'x402_demo' (controlled demo/test "
        "evidence) or 'x402_live' (real facilitator-verified x402). Defaults to "
        "the X402_MODE env var, else x402_demo.",
    )
    x402_payment: Optional[dict] = Field(
        default=None,
        description="Live mode only: the x402 payment payload (the decoded "
        "X-PAYMENT object) to verify/settle through the configured facilitator.",
    )
    save: bool = Field(default=True, description="Preserve artifacts locally.")


# ---------------------------------------------------------------------------
# Deterministic delivery
# ---------------------------------------------------------------------------

_TAG_RE = re.compile(r"<[^>]+>")
_WS_RE = re.compile(r"\s+")
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _strip_html(raw: str) -> str:
    """Deterministic, dependency-free text extraction from HTML/plain text."""
    no_scripts = re.sub(
        r"<(script|style)[^>]*>.*?</\1>", " ", raw, flags=re.IGNORECASE | re.DOTALL
    )
    text = _TAG_RE.sub(" ", no_scripts)
    return _WS_RE.sub(" ", text).strip()


def _extract_title(raw: str, fallback: str) -> str:
    match = _TITLE_RE.search(raw)
    if match:
        title = _WS_RE.sub(" ", _TAG_RE.sub(" ", match.group(1))).strip()
        if title:
            return title
    return fallback


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_digest(obj: Any) -> str:
    """sha256 over canonical (sorted-key, compact) JSON of the delivered object."""
    canonical = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + _sha256_hex(canonical.encode("utf-8"))


def build_delivery_object(inp: UrlSummaryInput, *, now: datetime) -> dict:
    """Produce the deterministic delivered evidence object for the request.

    For `url` mode this fetches the resource (real delivery). For `text` mode it
    summarizes inline text with no network. The returned object is the
    paid-for, delivered artifact; `delivery_evidence_digest` binds it."""
    if inp.text is not None:
        requested = inp.url or "inline:text"
        resolved = requested
        status_code = 200
        raw_text = inp.text
        content_bytes = raw_text.encode("utf-8")
        title = inp.title or "inline-text"
        cleaned = _WS_RE.sub(" ", raw_text).strip()
    elif inp.url:
        requested = inp.url
        try:
            resp = requests.get(
                inp.url,
                timeout=FETCH_TIMEOUT_SECONDS,
                headers={"User-Agent": USER_AGENT},
            )
        except requests.RequestException as exc:
            raise HTTPException(
                status_code=502,
                detail=f"url fetch failed for {inp.url!r}: {exc}",
            )
        resolved = str(resp.url)
        status_code = resp.status_code
        content_bytes = resp.content
        raw_text = resp.text
        title = _extract_title(raw_text, inp.title or requested)
        cleaned = _strip_html(raw_text)
    else:
        raise HTTPException(
            status_code=422, detail="provide either `url` or `text` to summarize"
        )

    word_count = len(cleaned.split())
    excerpt = cleaned[:EXCERPT_CHARS]
    content_sha256 = "sha256:" + _sha256_hex(content_bytes)
    delivered_at = now.isoformat().replace("+00:00", "Z")

    delivered = {
        "requested_url": requested,
        "resolved_url": resolved,
        "status_code": status_code,
        "title": title,
        "word_count": word_count,
        "content_sha256": content_sha256,
        "excerpt": excerpt,
        "delivered_at": delivered_at,
    }
    # The digest binds the whole delivered object (the strong delivery evidence).
    delivered["delivery_evidence_digest"] = _canonical_digest(delivered)
    return delivered


# ---------------------------------------------------------------------------
# Evidence-doc construction (committed `demo` ingestion shape)
# ---------------------------------------------------------------------------

def build_demo_x402_block(inp: UrlSummaryInput, delivered: dict, *, now: datetime) -> dict:
    """Build the explicit `x402_demo` payment block (NOT a real settlement).

    Carries demo-marked payer/tx/facilitator values so the demo nature is
    visible inside the generated receipt's payment block."""
    iso = lambda dt: dt.isoformat().replace("+00:00", "Z")
    quoted_at = iso(now - timedelta(seconds=5))
    expires_at = iso(now + timedelta(seconds=QUOTE_WINDOW_SECONDS))
    paid_at = iso(now - timedelta(seconds=2))
    verified_at = iso(now - timedelta(seconds=1))
    resource_url = delivered["requested_url"]

    x402: dict[str, Any] = {
        "quote": {
            "id": "quote_demo_" + _sha256_hex(resource_url.encode())[:16],
            "resource_url": resource_url,
            "price": {
                "value": DEMO_PRICE_VALUE,
                "currency": DEMO_PRICE_CURRENCY,
                "decimals": DEMO_PRICE_DECIMALS,
            },
            "pay_to": DEMO_PAY_TO,
            "network": DEMO_NETWORK,
            "quoted_at": quoted_at,
            "expires_at": expires_at,
        },
        "payment": {
            # Explicitly demo-marked payment evidence. Not a real settlement.
            "from": DEMO_PAYER,
            "tx": "x402_demo:" + delivered["delivery_evidence_digest"],
            "paid": {
                "value": DEMO_PRICE_VALUE,
                "currency": DEMO_PRICE_CURRENCY,
                "decimals": DEMO_PRICE_DECIMALS,
            },
            "paid_at": paid_at,
            "verified_at": verified_at,
            "facilitator": "x402_demo_facilitator",
            "authorized_from": [DEMO_PAYER],
        },
    }

    mode = (inp.mode or "record").strip().lower()
    if mode == "record":
        x402["delivery"] = {
            "url": resource_url,
            "evidence_type": "http_response",
            "content_digest": delivered["delivery_evidence_digest"],
            "http_status": delivered["status_code"],
            "served_at": delivered["delivered_at"],
        }
    return x402


def assemble_evidence_doc(
    inp: UrlSummaryInput,
    delivered: dict,
    x402: dict,
    *,
    payment_evidence: str,
    issuer_agent: str,
    now: datetime,
) -> dict:
    """Assemble the common evidence-doc envelope around an x402 payment block.

    `payment_evidence` ("x402_demo" | "x402_live") is carried explicitly so the
    mode is visible in the evidence doc and the preserved run report. Gate-mode
    authority handling is identical for both payment modes."""
    resource_url = delivered["requested_url"]
    mode = (inp.mode or "record").strip().lower()
    doc: dict[str, Any] = {
        "endpoint": "/pay/url-summary",
        "payment_evidence": payment_evidence,
        "mode": mode,
        "request": {"target_url": resource_url},
        "x402": x402,
        "issuer_agent": issuer_agent,
        "issued_at": now.isoformat().replace("+00:00", "Z"),
        "delivered_object": delivered,
        "authority": {
            "acting_party": "resource_server",
            "verifier_has_execution_authority": False,
        },
    }
    if mode == "gate":
        if not inp.gate_controller:
            raise HTTPException(
                status_code=422,
                detail="gate mode requires a gate_controller (the external "
                "system that controls release)",
            )
        doc["authority"]["gate_controller"] = inp.gate_controller
        if inp.release_policy:
            doc["authority"]["release_policy"] = inp.release_policy
    return doc


def build_demo_evidence_doc(inp: UrlSummaryInput, delivered: dict, *, now: datetime) -> dict:
    """Build the controlled `x402_demo` evidence doc in the committed
    `normalize_demo` shape (back-compat helper around the split builders)."""
    x402 = build_demo_x402_block(inp, delivered, now=now)
    return assemble_evidence_doc(
        inp,
        delivered,
        x402,
        payment_evidence=MODE_DEMO,
        issuer_agent=DEMO_ISSUER_AGENT,
        now=now,
    )


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

DEMO_NOTE = (
    "Controlled demo payment evidence — NOT a real on-chain settlement. See "
    "reports/sar402-demo/real-x402-payment-evidence-report-v0.1.md for the "
    "blocker to real x402 and the next bounded pass."
)
LIVE_NOTE = (
    "Real x402 payment evidence — verified (and, in record mode, settled) "
    "through the configured x402 facilitator. payment_ref is the real on-chain "
    "settlement transaction reference."
)


def build_evidence_for_mode(
    inp: UrlSummaryInput,
    delivered: dict,
    *,
    now: datetime,
    env: Optional[dict] = None,
    facilitator: Optional[FacilitatorClient] = None,
) -> tuple[dict, str]:
    """Resolve the payment mode and build the matching evidence doc.

    Returns `(evidence_doc, payment_evidence_label)`. The live path runs the
    real facilitator verify/settle flow and refuses to proceed unless the
    payment is actually verified — it never falls back to demo evidence."""
    config = load_x402_config(mode_override=inp.payment_mode, env=env)

    if config.mode == MODE_DEMO:
        x402 = build_demo_x402_block(inp, delivered, now=now)
        doc = assemble_evidence_doc(
            inp, delivered, x402,
            payment_evidence=MODE_DEMO,
            issuer_agent=DEMO_ISSUER_AGENT,
            now=now,
        )
        return doc, MODE_DEMO

    # ---- x402_live ---------------------------------------------------------
    record_mode = (inp.mode or "record").strip().lower() == "record"
    if not inp.x402_payment:
        raise HTTPException(
            status_code=422,
            detail="x402_live mode requires an `x402_payment` payload to verify "
            "through the configured facilitator. Refusing to label demo "
            "evidence as a real settlement.",
        )
    resource_url = delivered["requested_url"]
    result = verify_and_settle(
        config,
        resource=resource_url,
        payment_payload=inp.x402_payment,
        settle=record_mode,
        facilitator=facilitator,
    )
    x402 = build_live_x402_block(
        config, result,
        resource=resource_url,
        delivered=delivered,
        now=now,
        record_mode=record_mode,
    )
    issuer_agent = f"agent:attest-service:pay-url-summary-live:{config.network}"
    doc = assemble_evidence_doc(
        inp, delivered, x402,
        payment_evidence=MODE_LIVE,
        issuer_agent=issuer_agent,
        now=now,
    )
    return doc, MODE_LIVE


def run_url_summary(
    inp: UrlSummaryInput,
    *,
    env: Optional[dict] = None,
    facilitator: Optional[FacilitatorClient] = None,
) -> dict:
    """Pure (testable) core: deliver -> (demo|live) evidence -> committed
    SAR-402 -> result. `env`/`facilitator` are injectable for tests."""
    now = datetime.now(timezone.utc)
    delivered = build_delivery_object(inp, now=now)

    try:
        doc, payment_evidence = build_evidence_for_mode(
            inp, delivered, now=now, env=env, facilitator=facilitator
        )
    except X402ConfigError as exc:
        # Missing/invalid live config is a clear, bounded client error.
        raise HTTPException(status_code=400, detail=f"x402 config error: {exc}")
    except X402VerificationError as exc:
        # Payment could not be verified/settled — no receipt is produced.
        raise HTTPException(
            status_code=402, detail=f"x402 payment not verified: {exc}"
        )

    try:
        result = run_evidence_doc(
            doc,
            source="demo",
            save=inp.save,
            output_dir=DEMO_RUNS_DIR if inp.save else None,
        )
    except EvidenceError as exc:
        # Clean rejection of invalid / authority-violating evidence.
        raise HTTPException(status_code=422, detail=f"SAR-402 rejected evidence: {exc}")
    except Exception as exc:  # validation/build errors from the committed layer
        raise HTTPException(
            status_code=500, detail=f"SAR-402 receipt generation failed: {exc}"
        )

    receipt = result.receipt
    report = result.report or {}
    payment_block = receipt.get("payment") or {}
    return {
        "endpoint": "/pay/url-summary",
        "payment_evidence": payment_evidence,
        "payment_evidence_note": DEMO_NOTE if payment_evidence == MODE_DEMO else LIVE_NOTE,
        "delivered": delivered,
        "receipt_summary": {
            "schema_id": receipt.get("schema_id"),
            "profile": receipt.get("profile"),
            "sar_verdict": receipt.get("sar_verdict"),
            "verification_mode": receipt.get("verification_mode"),
            "verification_point": receipt.get("verification_point"),
            "payment_state": receipt.get("payment_state"),
            "delivery_state": receipt.get("delivery_state"),
            "settlement_state": receipt.get("settlement_state"),
            "continuity": receipt.get("continuity"),
            "authority_binding": receipt.get("authority_binding"),
            "integrity_digest": (receipt.get("integrity") or {}).get("digest"),
            "payment_ref": payment_block.get("payment_ref"),
            "facilitator": payment_block.get("facilitator"),
        },
        "artifacts": report.get("artifacts"),
        "run_id": report.get("run_id"),
        "receipt": receipt,
    }


@router.post("/pay/url-summary")
def pay_url_summary(input: UrlSummaryInput):
    """Paid URL-summary action that generates a SAR-402 receipt through the
    committed Morpheus SAR-402 package/layer, in `x402_demo` or `x402_live`
    payment mode."""
    return run_url_summary(input)
