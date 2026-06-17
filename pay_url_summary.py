"""Controlled `/pay/url-summary` demo endpoint — first live SAR-402 demo loop.

This module wires a controlled, x402-style paid URL-summary action to the
*committed, authoritative* SAR-402 builder/validator/ingestion layer living in
`/home/ubuntu/morpheus`. It does NOT hand-write receipts and it does NOT define a
new schema. It:

    1. accepts a controlled URL-summary request (a `url` to fetch, or inline
       `text` for a fully network-free run),
    2. produces *deterministic* delivery evidence for the requested action
       (requested_url, resolved_url, status_code, title, word_count,
       content_sha256, a short deterministic excerpt, delivered_at, and a
       delivery_evidence_digest binding all of it),
    3. normalizes payment + delivery evidence into the committed demo ingestion
       shape (`morpheus.sar402_agent.normalize_demo`),
    4. calls the committed Morpheus SAR-402 ingestion/runner
       (`run_evidence_doc`), which builds via the committed builder and
       re-validates via the committed validator,
    5. preserves source evidence, normalized view, receipt, and a run report
       locally under `reports/sar402-demo/runs/`,
    6. returns enough to inspect/link the generated receipt.

Authority boundary (non-negotiable): the verifier never holds execution
authority. This endpoint performs the (controlled) delivery and *records* the
result through SAR-402; SAR-402 does not gate, release, or move anything. In
gate mode an external, non-forbidden `gate_controller` is named — never the
verifier / Default Settlement / Morpheus / SettlementWitness / SAR-402 itself.

Payment evidence honesty: no real wallet/facilitator is wired in this pass, so
the payment leg runs in an explicit, clearly-labelled `x402_demo` mode. The
payment block carries demo-marked payer/tx values and the run report records
`payment_evidence: "x402_demo"`. Demo evidence is never labelled as a real
on-chain settlement. See `reports/sar402-demo/url-summary-demo-report-v0.1.md`
for the exact blocker to a real x402 payment and the next bounded pass.
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

def build_demo_evidence_doc(inp: UrlSummaryInput, delivered: dict, *, now: datetime) -> dict:
    """Build the controlled demo-evidence doc in the committed `normalize_demo`
    shape. The payment leg is explicit `x402_demo` evidence (not a real payment).

    The paid-for resource identity is the requested_url; in record mode the
    delivered resource url is the same identity, so object/executor continuity
    can resolve cleanly to PASS from real delivery evidence."""
    iso = lambda dt: dt.isoformat().replace("+00:00", "Z")
    quoted_at = iso(now - timedelta(seconds=5))
    expires_at = iso(now + timedelta(seconds=QUOTE_WINDOW_SECONDS))
    paid_at = iso(now - timedelta(seconds=2))
    verified_at = iso(now - timedelta(seconds=1))
    issued_at = iso(now)

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

    doc: dict[str, Any] = {
        "endpoint": "/pay/url-summary",
        "payment_evidence": "x402_demo",
        "mode": mode,
        "request": {"target_url": resource_url},
        "x402": x402,
        "issuer_agent": DEMO_ISSUER_AGENT,
        "issued_at": issued_at,
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


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

def run_url_summary(inp: UrlSummaryInput) -> dict:
    """Pure (testable) core: deliver -> normalize -> committed SAR-402 -> result."""
    now = datetime.now(timezone.utc)
    delivered = build_delivery_object(inp, now=now)
    doc = build_demo_evidence_doc(inp, delivered, now=now)

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
    return {
        "endpoint": "/pay/url-summary",
        "payment_evidence": "x402_demo",
        "payment_evidence_note": (
            "Controlled demo payment evidence — NOT a real on-chain settlement. "
            "See reports/sar402-demo/url-summary-demo-report-v0.1.md for the "
            "blocker to real x402 and the next bounded pass."
        ),
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
        },
        "artifacts": report.get("artifacts"),
        "run_id": report.get("run_id"),
        "receipt": receipt,
    }


@router.post("/pay/url-summary")
def pay_url_summary(input: UrlSummaryInput):
    """Controlled paid URL-summary action that generates a SAR-402 receipt
    through the committed Morpheus SAR-402 package/layer."""
    return run_url_summary(input)
