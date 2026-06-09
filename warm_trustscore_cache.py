from __future__ import annotations

import argparse
import sys
from typing import Any
from urllib.parse import quote

import requests

import attest_service

DEFAULT_TIMEOUT_SECONDS = 30.0


def fetch_trustscore(agent_id: str, timeout_seconds: float) -> dict[str, Any] | None:
    url = f"{attest_service.TRUSTSCORE_URL_BASE}/{quote(agent_id, safe='')}"
    response = requests.get(url, timeout=timeout_seconds)
    response.raise_for_status()
    data = response.json()
    trustscore = data.get("trustscore_v1") if isinstance(data, dict) else None
    return trustscore if isinstance(trustscore, dict) else None


def main() -> int:
    parser = argparse.ArgumentParser(description="Warm the local TrustScore cache for one agent.")
    parser.add_argument("agent_id", help="Agent ID to fetch from settlement-witness.")
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"Settlement-witness request timeout in seconds. Default: {DEFAULT_TIMEOUT_SECONDS:g}",
    )
    args = parser.parse_args()

    try:
        trustscore = fetch_trustscore(args.agent_id, args.timeout)
    except (requests.RequestException, ValueError) as exc:
        print(f"error: failed to fetch TrustScore for {args.agent_id}: {exc}", file=sys.stderr)
        return 1

    if trustscore is None or trustscore.get("score") is None:
        print(f"error: no TrustScore score returned for {args.agent_id}", file=sys.stderr)
        return 1

    cached = attest_service.store_trustscore(args.agent_id, trustscore)
    score = cached.get("score")
    tier = cached.get("tier")
    print(f"agent_id={args.agent_id} score={score} tier={tier} cache={attest_service.TRUSTSCORE_CACHE_FILE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
