"""Live x402 payment-evidence boundary for `/pay/url-summary`.

This module is the **honest live-payment boundary** for the SAR-402 demo loop. It
does NOT define a new schema, hand-write receipts, or weaken the authority
boundary. It only:

    1. loads + validates the live x402 configuration (env / config),
    2. defines the standard x402 *facilitator* verify/settle request-response
       adapter (the documented Coinbase CDP / x402 facilitator flow),
    3. normalizes a *real, facilitator-verified* x402 payment into the same
       `x402` evidence-doc shape the committed `morpheus.sar402_agent.normalize_demo`
       already consumes — preserving the raw facilitator/quote/payment payloads,
    4. refuses to mark a payment `verified` unless the facilitator actually
       verified (and, for record mode, settled) it.

Honesty rule (non-negotiable): the committed record-mode builder always stamps
`payment_state: verified`. Therefore this boundary only ever hands evidence to
the committed builder *after* a real facilitator verification has succeeded. If
required config is missing, or verification/settlement is incomplete, we raise —
we never produce a `verified` receipt from unverified payment, and we never fall
back to demo evidence while calling it live.

No secrets are logged or written. `X402_PAYER_PRIVATE_KEY` is read only if a
local signing flow is wired (not in this pass) and is never echoed or persisted.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Mapping, Optional

import requests

# x402 payment evidence modes. These are the *only* two; there is no third
# "silently-demo-but-labelled-live" state.
MODE_DEMO = "x402_demo"
MODE_LIVE = "x402_live"
SUPPORTED_PAYMENT_MODES = (MODE_DEMO, MODE_LIVE)

X402_VERSION = 1
DEFAULT_QUOTE_WINDOW_SECONDS = 600
FACILITATOR_TIMEOUT_SECONDS = 20

# Convenience CAIP-2 mapping for human-friendly network names. The canonical
# evidence value is always CAIP-2 (e.g. "eip155:8453"); "base" is sugar.
NETWORK_CAIP2 = {
    "base": "eip155:8453",
    "base-sepolia": "eip155:84532",
    "base-mainnet": "eip155:8453",
    "polygon": "eip155:137",
    "ethereum": "eip155:1",
}


class X402ConfigError(Exception):
    """Live x402 configuration is missing or invalid (a clear, bounded failure)."""


class X402VerificationError(Exception):
    """A live x402 payment could not be verified/settled by the facilitator.

    Raising this is the honest outcome: no `verified` receipt is produced."""


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class X402Config:
    """Resolved live x402 configuration.

    Field names mirror the documented env vars. `payer_private_key` is carried
    only so a future local-signing flow can use it; it is never serialized,
    logged, or written to artifacts."""

    mode: str
    facilitator_url: Optional[str] = None
    pay_to: Optional[str] = None
    network: Optional[str] = None        # CAIP-2, e.g. "eip155:8453"
    asset: Optional[str] = None          # human symbol, e.g. "USDC"
    asset_address: Optional[str] = None  # on-chain token contract (optional)
    asset_decimals: int = 6
    amount: Optional[str] = None         # integer string, smallest unit
    payer_address: Optional[str] = None
    payer_private_key: Optional[str] = field(default=None, repr=False)
    quote_window_seconds: int = DEFAULT_QUOTE_WINDOW_SECONDS

    @property
    def is_live(self) -> bool:
        return self.mode == MODE_LIVE

    def public_dict(self) -> dict:
        """Config view safe to log / write to reports. Never includes the key."""
        return {
            "mode": self.mode,
            "facilitator_url": self.facilitator_url,
            "pay_to": self.pay_to,
            "network": self.network,
            "asset": self.asset,
            "asset_address": self.asset_address,
            "asset_decimals": self.asset_decimals,
            "amount": self.amount,
            "payer_address": self.payer_address,
            "payer_private_key_present": bool(self.payer_private_key),
        }


def _normalize_network(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    return NETWORK_CAIP2.get(value.strip().lower(), value.strip())


def _resolve_mode(explicit: Optional[str], env: Mapping[str, str]) -> str:
    """Resolve the effective payment mode (request override > env > demo)."""
    raw = (explicit or env.get("X402_MODE") or MODE_DEMO).strip().lower()
    # Accept friendly aliases but normalize to the canonical token.
    if raw in ("demo", "x402_demo"):
        return MODE_DEMO
    if raw in ("live", "x402_live"):
        return MODE_LIVE
    raise X402ConfigError(
        f"unknown X402 payment mode {raw!r}; expected one of {SUPPORTED_PAYMENT_MODES}"
    )


def load_x402_config(
    *,
    mode_override: Optional[str] = None,
    env: Optional[Mapping[str, str]] = None,
) -> X402Config:
    """Load + validate live x402 config from the environment.

    `mode_override` (from the request) takes precedence over `X402_MODE`. In
    demo mode no live fields are required. In live mode the required fields are
    validated up front and a clear `X402ConfigError` lists everything missing —
    so a live request can never silently run on partial/demo evidence."""
    env = os.environ if env is None else env
    mode = _resolve_mode(mode_override, env)

    config = X402Config(
        mode=mode,
        facilitator_url=(env.get("X402_FACILITATOR_URL") or None),
        pay_to=(env.get("X402_PAY_TO") or None),
        network=_normalize_network(env.get("X402_NETWORK")),
        asset=(env.get("X402_ASSET") or None),
        asset_address=(env.get("X402_ASSET_ADDRESS") or None),
        asset_decimals=int(env.get("X402_ASSET_DECIMALS") or 6),
        amount=(env.get("X402_AMOUNT") or None),
        payer_address=(env.get("X402_PAYER_ADDRESS") or None),
        payer_private_key=(env.get("X402_PAYER_PRIVATE_KEY") or None),
        quote_window_seconds=int(
            env.get("X402_QUOTE_WINDOW_SECONDS") or DEFAULT_QUOTE_WINDOW_SECONDS
        ),
    )

    if config.is_live:
        missing = [
            name
            for name, value in (
                ("X402_FACILITATOR_URL", config.facilitator_url),
                ("X402_PAY_TO", config.pay_to),
                ("X402_NETWORK", config.network),
                ("X402_ASSET", config.asset),
                ("X402_AMOUNT", config.amount),
                ("X402_PAYER_ADDRESS", config.payer_address),
            )
            if not value
        ]
        if missing:
            raise X402ConfigError(
                "x402_live mode requires configuration that is not set: "
                + ", ".join(missing)
                + ". Set these env vars (see "
                "reports/sar402-demo/real-x402-payment-evidence-report-v0.1.md) "
                "or use payment_mode=x402_demo for the controlled demo loop."
            )
    return config


# ---------------------------------------------------------------------------
# x402 facilitator adapter (standard verify / settle flow)
# ---------------------------------------------------------------------------

def build_payment_requirements(config: X402Config, *, resource: str) -> dict:
    """Construct the standard x402 `PaymentRequirements` object.

    This mirrors the documented x402 facilitator schema: `scheme`, `network`,
    `maxAmountRequired`, `resource`, `payTo`, `asset`, and `extra`. The
    facilitator verifies a payment payload against this object."""
    return {
        "scheme": "exact",
        "network": config.network,
        "maxAmountRequired": config.amount,
        "resource": resource,
        "description": "attest-service /pay/url-summary",
        "mimeType": "application/json",
        "payTo": config.pay_to,
        "maxTimeoutSeconds": config.quote_window_seconds,
        "asset": config.asset_address or config.asset,
        "extra": {
            "symbol": config.asset,
            "decimals": config.asset_decimals,
        },
    }


@dataclass
class FacilitatorResult:
    """Outcome of a facilitator verify (+ optional settle) round-trip."""

    is_valid: bool
    payer: Optional[str]
    transaction: Optional[str]
    settled: bool
    verify_raw: dict
    settle_raw: Optional[dict]
    invalid_reason: Optional[str] = None


class FacilitatorClient:
    """HTTP adapter for the standard x402 facilitator `/verify` + `/settle` flow.

    Default implementation targets the documented x402 facilitator endpoints
    (compatible with the Coinbase CDP facilitator request/response shape). It is
    intentionally injectable so tests can supply real-shaped responses without a
    live network/wallet, and so an alternative documented facilitator can be
    swapped in without touching the evidence-normalization path."""

    def __init__(self, base_url: str, *, session: Optional[Any] = None,
                 timeout: int = FACILITATOR_TIMEOUT_SECONDS) -> None:
        self.base_url = base_url.rstrip("/")
        self._session = session or requests
        self._timeout = timeout

    def _post(self, path: str, payload: dict) -> dict:
        resp = self._session.post(
            f"{self.base_url}{path}", json=payload, timeout=self._timeout
        )
        try:
            data = resp.json()
        except ValueError:
            data = {"error": getattr(resp, "text", "")}
        if getattr(resp, "status_code", 200) >= 400:
            raise X402VerificationError(
                f"facilitator {path} returned {resp.status_code}: {data}"
            )
        return data

    def verify(self, requirements: dict, payment_payload: dict) -> dict:
        return self._post(
            "/verify",
            {
                "x402Version": X402_VERSION,
                "paymentPayload": payment_payload,
                "paymentRequirements": requirements,
            },
        )

    def settle(self, requirements: dict, payment_payload: dict) -> dict:
        return self._post(
            "/settle",
            {
                "x402Version": X402_VERSION,
                "paymentPayload": payment_payload,
                "paymentRequirements": requirements,
            },
        )


def verify_and_settle(
    config: X402Config,
    *,
    resource: str,
    payment_payload: Mapping[str, Any],
    settle: bool,
    facilitator: Optional[FacilitatorClient] = None,
) -> FacilitatorResult:
    """Run the standard x402 facilitator verification (and optional settlement).

    Returns a `FacilitatorResult` only when the facilitator reports the payment
    valid. Raises `X402VerificationError` on any incomplete/invalid result, so a
    caller can never mistake an unverified payment for a verified one.

    `settle=True` (record / post-delivery) additionally requires a successful
    on-chain settlement that yields a real transaction reference."""
    if not config.is_live:
        raise X402ConfigError("verify_and_settle is only valid in x402_live mode")
    if facilitator is None:
        facilitator = FacilitatorClient(config.facilitator_url)

    requirements = build_payment_requirements(config, resource=resource)

    verify_raw = facilitator.verify(requirements, dict(payment_payload))
    is_valid = bool(verify_raw.get("isValid"))
    invalid_reason = verify_raw.get("invalidReason")
    verified_payer = verify_raw.get("payer") or payment_payload.get("payer")

    if not is_valid:
        raise X402VerificationError(
            f"facilitator did not verify payment: {invalid_reason or 'isValid=false'}"
        )

    # Honesty check: the facilitator-confirmed payer must match the configured
    # payer; a mismatch is a real authority discrepancy, not something to paper
    # over.
    if (
        verified_payer
        and config.payer_address
        and verified_payer.lower() != config.payer_address.lower()
    ):
        raise X402VerificationError(
            "facilitator-confirmed payer does not match X402_PAYER_ADDRESS"
        )

    settle_raw: Optional[dict] = None
    transaction: Optional[str] = None
    settled = False
    if settle:
        settle_raw = facilitator.settle(requirements, dict(payment_payload))
        settled = bool(settle_raw.get("success"))
        transaction = settle_raw.get("transaction") or settle_raw.get("txHash")
        if not settled or not transaction:
            raise X402VerificationError(
                "facilitator settlement incomplete: "
                f"{settle_raw.get('errorReason') or 'no transaction reference'}"
            )

    return FacilitatorResult(
        is_valid=True,
        payer=verified_payer or config.payer_address,
        transaction=transaction,
        settled=settled,
        verify_raw=verify_raw,
        settle_raw=settle_raw,
        invalid_reason=invalid_reason,
    )


# ---------------------------------------------------------------------------
# Live evidence-doc construction (same committed `normalize_demo` x402 shape)
# ---------------------------------------------------------------------------

def _iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def build_live_x402_block(
    config: X402Config,
    result: FacilitatorResult,
    *,
    resource: str,
    delivered: Optional[dict],
    now: datetime,
    record_mode: bool,
) -> dict:
    """Build the `x402` evidence sub-doc from a *verified* facilitator result.

    Same field names the committed `normalize_demo` consumes (quote / payment /
    delivery). Raw facilitator payloads are preserved alongside as
    `quote_raw` / `payment_raw` without altering the SAR-402 schema."""
    quoted_at = _iso(now - timedelta(seconds=2))
    expires_at = _iso(now + timedelta(seconds=config.quote_window_seconds))
    verified_at = _iso(now)

    price = {
        "value": config.amount,
        "currency": config.asset,
        "decimals": config.asset_decimals,
    }
    quote_id = "quote_live_" + (result.transaction or resource)[:24]

    x402: dict[str, Any] = {
        "quote": {
            "id": quote_id,
            "resource_url": resource,
            "price": price,
            "pay_to": config.pay_to,
            "network": config.network,
            "quoted_at": quoted_at,
            "expires_at": expires_at,
        },
        "payment": {
            "from": result.payer,
            # Real on-chain settlement reference — NOT an `x402_demo:` synthetic.
            "tx": result.transaction or "",
            "paid": dict(price),
            "paid_at": verified_at,
            "verified_at": verified_at,
            "facilitator": config.facilitator_url,
            "authorized_from": [config.payer_address],
        },
        # Raw facilitator evidence preserved (schema-agnostic extra fields).
        "quote_raw": build_payment_requirements(config, resource=resource),
        "payment_raw": {
            "verify": result.verify_raw,
            "settle": result.settle_raw,
        },
    }

    if record_mode:
        if not delivered:
            raise X402VerificationError(
                "record (post-delivery) mode requires delivery evidence"
            )
        x402["delivery"] = {
            "url": resource,
            "evidence_type": "http_response",
            "content_digest": delivered["delivery_evidence_digest"],
            "http_status": delivered["status_code"],
            "served_at": delivered["delivered_at"],
        }
    return x402
