"""Hosted Path C, Step 2B: SIGNED Continuity Evaluation Receipt issuance.

Step 2A (``deterministic_evaluation_store`` / ``deterministic_evaluator``)
produces and stores an UNSIGNED deterministic evaluation record for a committed
``action_ref``. Step 2B takes that already-stored unsigned record and issues a
SIGNED Continuity Evaluation Receipt over its evaluation state — without
touching, re-evaluating, or signing the Step 2A record.

Canonical model (mirrors the SDK
``defaultsettlement-sdk/packages/continuity/src/continuity-evaluation.ts``,
``schema_id: ds.continuity_evaluation.v0.1``). The signed core fields are:

    schema_id, action_ref, evaluator_id, evaluation_state, policy_ref,
    evaluated_at

and a top-level ``signature`` envelope that is EXCLUDED from the signing input:

    signed_core = receipt without its ``signature`` block
    signature   = Ed25519.sign( JCS(signed_core) )
    signature.alg        = "ed25519"
    signature.key_id     = evaluator_id   (identity-to-key binding)
    signature.public_key = base64 SPKI DER of the Ed25519 public key
    signature.signature  = base64 Ed25519 signature over JCS(signed_core)

Bounded claim (and nothing more). A signed Continuity Evaluation Receipt proves
only that the named evaluator signed the pre-execution evaluation state for the
committed ``action_ref`` under the stated ``policy_ref``. It does NOT prove
actual downstream release, payment finality, resource-release finality,
execution, objective correctness, or legal sufficiency.

Key material is NEVER printed, logged, or persisted. Only the public key (as
base64 SPKI DER) is embedded in the signature envelope.
"""

from __future__ import annotations

import base64
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Optional

try:
    import fcntl
except ImportError:  # pragma: no cover - non-posix
    fcntl = None

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# Reuse the committed-chain canonicalization + json helpers so this module's
# signing input value-domain cannot drift from the Step 2A store / evaluator.
# ``canonical_json_bytes`` is sorted-keys + compact-separators + UTF-8.
from action_commitment_store import _is_sha256, canonical_json_bytes

BASE_DIR = Path(__file__).resolve().parent

# Separate, append-only Step 2B ledger (NOT the Step 2A evaluation ledger, NOT
# the action commitment ledger, NOT the SAR-402 ledgers). Tests monkeypatch
# this; never written on import.
CONTINUITY_EVALUATION_RECEIPT_LEDGER = (
    BASE_DIR / "attest_continuity_evaluation_receipts_master.jsonl"
)

SCHEMA_ID = "ds.continuity_evaluation.v0.1"
SIGNATURE_ALG = "ed25519"

# Mirrors EVALUATION_STATES in the SDK. The Step 2A ``result`` domain is the
# same set, so an unsigned result maps 1:1 to an evaluation_state.
EVALUATION_STATES = frozenset(
    {"PASS", "FAIL", "INDETERMINATE", "EVALUATOR_TIMEOUT"}
)

# Mirrors AGENT_ID_RE in @defaultsettlement/canonical.
import re

_AGENT_ID_RE = re.compile(r"^agent:[a-z0-9]+(?::[A-Za-z0-9._-]+)*$")

# Env config keys.
ENV_EVALUATOR_ID = "DS_CONTINUITY_EVALUATOR_ID"
ENV_PRIVATE_KEY_B64 = "DS_CONTINUITY_EVALUATOR_PRIVATE_KEY_B64"
ENV_PUBLIC_KEY_B64 = "DS_CONTINUITY_EVALUATOR_PUBLIC_KEY_B64"
ENV_POLICY_REF = "DS_CONTINUITY_POLICY_REF"

# Explicit, safe defaults (identity + policy only — NEVER a default key).
# NOTE: the suggested form "agent:defaultverifier-continuity-v1" is NOT valid
# under the canonical AGENT_ID_RE (a hyphen is not allowed in the FIRST label;
# only colon-separated trailing labels may contain ``-._``). We therefore use
# the colon-scoped, canonically-valid equivalent so receipts validate under the
# SDK's validateAgentId / @defaultsettlement/canonical.
DEFAULT_EVALUATOR_ID = "agent:defaultverifier:continuity-v1"
DEFAULT_POLICY_REF = (
    "policy:default-settlement/sar-402-deterministic-conditional-release-v1"
)

# Bounded-claim string stamped onto the issuance response (NOT into the signed
# core, whose shape must match ds.continuity_evaluation.v0.1 exactly).
BOUNDED_CLAIM = (
    "A signed Continuity Evaluation Receipt proves only that the named evaluator "
    "signed the pre-execution evaluation state for the committed action_ref under "
    "the stated policy_ref. It does NOT prove actual downstream release, payment "
    "finality, resource-release finality, execution, objective correctness, or "
    "legal sufficiency."
)


class ContinuityReceiptError(ValueError):
    """The receipt shape/inputs are invalid and a receipt cannot be issued."""


class ContinuityReceiptConfigError(ContinuityReceiptError):
    """Signing was requested but key/config material is missing or invalid.

    Raised so the service can fail SAFELY (no unsigned/partial receipt is ever
    produced or stored when signing cannot be performed)."""


class ContinuityReceiptConflict(ContinuityReceiptError):
    """A different signed receipt already exists for the same action_ref.

    One signed Continuity Evaluation Receipt per action_ref; never overwritten."""


class ContinuityReceiptVerificationError(ContinuityReceiptError):
    """A receipt failed cryptographic / identity-binding verification."""


# ---------------------------------------------------------------------------
# Minimal JSONL helpers for the signed Step 2B receipt store
# ---------------------------------------------------------------------------

def _append_jsonl(path: Path, record: Mapping[str, Any]) -> None:
    import json
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


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    import json
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


# ---------------------------------------------------------------------------
# Format helpers
# ---------------------------------------------------------------------------

def is_valid_action_ref(value: Any) -> bool:
    """Return True when value is a valid sha256:<64 hex> action_ref."""
    return _is_sha256(value)


def _is_valid_evaluator_id(value: Any) -> bool:
    return isinstance(value, str) and bool(_AGENT_ID_RE.match(value))


def _now_iso_utc() -> str:
    """Fresh UTC ISO-8601 timestamp generated at signing time (Z suffix).

    Matches the service's timestamp convention. This is NEVER derived from the
    Step 2A record's contents."""
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


# ---------------------------------------------------------------------------
# Key material (Ed25519 via python-cryptography). Never printed or persisted.
# ---------------------------------------------------------------------------

def _load_private_key_from_b64(b64: str) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from base64.

    Accepts (in order): the 32-byte raw Ed25519 seed, or a PKCS8 DER private
    key, both base64-encoded. The raw-seed form is the smallest, dependency-free
    representation and is the documented primary form for
    ``DS_CONTINUITY_EVALUATOR_PRIVATE_KEY_B64``."""
    try:
        raw = base64.b64decode(b64, validate=True)
    except Exception as exc:  # noqa: BLE001
        raise ContinuityReceiptConfigError(
            f"{ENV_PRIVATE_KEY_B64} is not valid base64"
        ) from exc
    if len(raw) == 32:
        try:
            return Ed25519PrivateKey.from_private_bytes(raw)
        except Exception as exc:  # noqa: BLE001
            raise ContinuityReceiptConfigError(
                f"{ENV_PRIVATE_KEY_B64} is not a valid 32-byte Ed25519 seed"
            ) from exc
    # Fall back to PKCS8 DER.
    try:
        key = serialization.load_der_private_key(raw, password=None)
    except Exception as exc:  # noqa: BLE001
        raise ContinuityReceiptConfigError(
            f"{ENV_PRIVATE_KEY_B64} must be a base64 32-byte Ed25519 seed or "
            "PKCS8 DER private key"
        ) from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ContinuityReceiptConfigError(
            f"{ENV_PRIVATE_KEY_B64} is not an Ed25519 private key"
        )
    return key


def _public_key_spki_b64(public_key: Ed25519PublicKey) -> str:
    """Export an Ed25519 public key as base64 SPKI DER (the public_key field form)."""
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(der).decode("ascii")


def _load_public_key_from_spki_b64(b64: str) -> Ed25519PublicKey:
    try:
        der = base64.b64decode(b64, validate=True)
        key = serialization.load_der_public_key(der)
    except Exception as exc:  # noqa: BLE001
        raise ContinuityReceiptVerificationError(
            "signature.public_key is not a valid Ed25519 SPKI public key"
        ) from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ContinuityReceiptVerificationError(
            "signature.public_key is not an Ed25519 public key"
        )
    return key


# ---------------------------------------------------------------------------
# Config loader. Fails SAFELY when signing is requested but key is missing.
# ---------------------------------------------------------------------------

class EvaluatorSigningConfig:
    """Resolved Step 2B signing config: identity, policy, and a private key.

    Constructed only when signing is actually requested. If the private key is
    absent/invalid, construction raises ``ContinuityReceiptConfigError`` so no
    unsigned/partial receipt is produced."""

    def __init__(
        self,
        evaluator_id: str,
        policy_ref: str,
        private_key: Ed25519PrivateKey,
    ) -> None:
        self.evaluator_id = evaluator_id
        self.policy_ref = policy_ref
        self._private_key = private_key
        self.public_key = private_key.public_key()
        self.public_key_b64 = _public_key_spki_b64(self.public_key)

    @classmethod
    def from_env(cls, env: Optional[Mapping[str, str]] = None) -> "EvaluatorSigningConfig":
        env = os.environ if env is None else env

        evaluator_id = env.get(ENV_EVALUATOR_ID) or DEFAULT_EVALUATOR_ID
        if not _is_valid_evaluator_id(evaluator_id):
            raise ContinuityReceiptConfigError(
                f"{ENV_EVALUATOR_ID} must use the agent: identity scheme; "
                f"got {evaluator_id!r}"
            )

        policy_ref = env.get(ENV_POLICY_REF) or DEFAULT_POLICY_REF
        if not isinstance(policy_ref, str) or policy_ref.strip() == "":
            raise ContinuityReceiptConfigError(
                f"{ENV_POLICY_REF} must be a non-empty stable string reference"
            )

        priv_b64 = env.get(ENV_PRIVATE_KEY_B64)
        if not priv_b64:
            # SAFE FAILURE: signing requested, no key material. Do not fabricate
            # a key, do not emit an unsigned receipt.
            raise ContinuityReceiptConfigError(
                f"{ENV_PRIVATE_KEY_B64} is not set; cannot issue a signed "
                "Continuity Evaluation Receipt (refusing to produce an unsigned "
                "or partial receipt)"
            )
        private_key = _load_private_key_from_b64(priv_b64)

        # Optional public-key pin: if provided, it MUST match the private key's
        # public key (guards against mismatched key material in config).
        pub_b64 = env.get(ENV_PUBLIC_KEY_B64)
        if pub_b64:
            derived = _public_key_spki_b64(private_key.public_key())
            if pub_b64.strip() != derived:
                raise ContinuityReceiptConfigError(
                    f"{ENV_PUBLIC_KEY_B64} does not match the public key derived "
                    f"from {ENV_PRIVATE_KEY_B64}"
                )

        return cls(evaluator_id, policy_ref, private_key)

    def sign_bytes(self, message: bytes) -> bytes:
        return self._private_key.sign(message)


# ---------------------------------------------------------------------------
# Core build / sign / verify
# ---------------------------------------------------------------------------

def build_continuity_evaluation_core(
    *,
    action_ref: str,
    evaluation_state: str,
    evaluator_id: str,
    policy_ref: str,
    evaluated_at: str,
) -> dict[str, Any]:
    """Build + validate the unsigned canonical core (ds.continuity_evaluation.v0.1)."""
    if not _is_sha256(action_ref):
        raise ContinuityReceiptError("action_ref must be sha256:<64 hex>")
    if evaluation_state not in EVALUATION_STATES:
        raise ContinuityReceiptError(
            "evaluation_state must be one of " + ", ".join(sorted(EVALUATION_STATES))
        )
    if not _is_valid_evaluator_id(evaluator_id):
        raise ContinuityReceiptError(
            "evaluator_id must use the agent: identity scheme"
        )
    if not isinstance(policy_ref, str) or policy_ref.strip() == "":
        raise ContinuityReceiptError(
            "policy_ref is required and must be a non-empty stable string reference"
        )
    if not isinstance(evaluated_at, str) or evaluated_at.strip() == "":
        raise ContinuityReceiptError("evaluated_at must be an RFC 3339 timestamp")
    return {
        "schema_id": SCHEMA_ID,
        "action_ref": action_ref,
        "evaluator_id": evaluator_id,
        "evaluation_state": evaluation_state,
        "policy_ref": policy_ref,
        "evaluated_at": evaluated_at,
    }


def _signed_core(receipt: Mapping[str, Any]) -> dict[str, Any]:
    """Strip the ``signature`` block, returning the canonical signed core."""
    return {k: v for k, v in receipt.items() if k != "signature"}


def canonical_signing_input(receipt: Mapping[str, Any]) -> bytes:
    """The exact bytes that are signed: JCS(signed_core) as UTF-8.

    ``signature`` is excluded from the signing input."""
    return canonical_json_bytes(_signed_core(receipt))


def sign_continuity_evaluation_receipt(
    core: Mapping[str, Any], config: EvaluatorSigningConfig
) -> dict[str, Any]:
    """Sign a canonical core, producing ``core + {signature}``.

    ``signature.key_id`` is bound to the core's ``evaluator_id``."""
    if "signature" in core:
        raise ContinuityReceiptError(
            "cannot sign a record that already carries a signature block"
        )
    if core.get("evaluator_id") != config.evaluator_id:
        raise ContinuityReceiptError(
            "core.evaluator_id must equal the configured evaluator_id"
        )
    message = canonical_json_bytes(core)
    signature = config.sign_bytes(message)
    receipt = dict(core)
    receipt["signature"] = {
        "alg": SIGNATURE_ALG,
        "key_id": config.evaluator_id,
        "public_key": config.public_key_b64,
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    return receipt


def verify_continuity_evaluation_receipt(
    receipt: Mapping[str, Any], expected_public_key_b64: str
) -> dict[str, Any]:
    """Verify a signed receipt; return its canonical core or raise.

    Enforces identity-to-signing-key binding:
      1. ``signature.key_id`` MUST equal the record's ``evaluator_id``;
      2. ``signature.public_key`` MUST equal the trusted ``expected_public_key_b64``
         bound to that identity;
      3. the Ed25519 signature MUST verify over JCS(signed_core) under that key.

    The trusted key is supplied by the caller; no key discovery happens here."""
    sig = receipt.get("signature")
    if not isinstance(sig, Mapping):
        raise ContinuityReceiptVerificationError("record has no signature block")
    if sig.get("alg") != SIGNATURE_ALG:
        raise ContinuityReceiptVerificationError(
            f"signature.alg must be {SIGNATURE_ALG}"
        )
    key_id = sig.get("key_id")
    public_key_b64 = sig.get("public_key")
    sig_b64 = sig.get("signature")
    if not all(isinstance(v, str) for v in (key_id, public_key_b64, sig_b64)):
        raise ContinuityReceiptVerificationError(
            "signature block is missing key_id, public_key, or signature"
        )

    # (1) signer identity binding: key_id MUST equal evaluator_id.
    evaluator_id = receipt.get("evaluator_id")
    if key_id != evaluator_id:
        raise ContinuityReceiptVerificationError(
            f"signature.key_id {key_id} does not match evaluator_id {evaluator_id}"
        )
    # (2) the presented key must be the identity-bound trusted key.
    if public_key_b64 != expected_public_key_b64:
        raise ContinuityReceiptVerificationError(
            "signing key does not match the trusted public key bound to the "
            "signer identity"
        )
    # (3) cryptographic verification over the canonical signing input.
    public_key = _load_public_key_from_spki_b64(public_key_b64)
    message = canonical_signing_input(receipt)
    try:
        signature = base64.b64decode(sig_b64, validate=True)
    except Exception as exc:  # noqa: BLE001
        raise ContinuityReceiptVerificationError(
            "signature.signature is not valid base64"
        ) from exc
    try:
        public_key.verify(signature, message)
    except InvalidSignature as exc:
        raise ContinuityReceiptVerificationError(
            "Ed25519 signature verification failed"
        ) from exc
    return _signed_core(receipt)


# ---------------------------------------------------------------------------
# Store / retrieve (append-only JSONL; one signed receipt per action_ref)
# ---------------------------------------------------------------------------

def get_continuity_evaluation_receipt(action_ref: str) -> Optional[dict[str, Any]]:
    """Return the stored signed receipt for ``action_ref``, or None."""
    if not _is_sha256(action_ref):
        return None
    latest: Optional[dict[str, Any]] = None
    for record in _read_jsonl(CONTINUITY_EVALUATION_RECEIPT_LEDGER):
        if record.get("action_ref") == action_ref:
            latest = record
    return latest


def store_continuity_evaluation_receipt(receipt: Mapping[str, Any]) -> bool:
    """Persist a signed receipt. Returns True iff a new record was written.

    Behavior (idempotent, never overwrites):
      * no receipt exists for the action_ref -> append, return True;
      * a canonically-identical receipt exists -> no write, return False;
      * any canonically-different signed receipt exists for the same action_ref
        -> raise ``ContinuityReceiptConflict``."""
    action_ref = receipt.get("action_ref")
    if not _is_sha256(action_ref):
        raise ContinuityReceiptError("action_ref must be sha256:<64 hex>")
    if not isinstance(receipt.get("signature"), Mapping):
        raise ContinuityReceiptError("refusing to store an unsigned receipt")

    existing = get_continuity_evaluation_receipt(action_ref)
    if existing is not None:
        if canonical_json_bytes(existing) == canonical_json_bytes(receipt):
            return False  # idempotent: identical signed receipt already stored
        raise ContinuityReceiptConflict(
            "a different signed Continuity Evaluation Receipt already exists for "
            f"action_ref {action_ref!r}; one signed receipt per action_ref — it "
            "is never overwritten"
        )

    _append_jsonl(CONTINUITY_EVALUATION_RECEIPT_LEDGER, dict(receipt))
    return True
